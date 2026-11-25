<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning\Users;

use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Provisioning\ProvisioningCaller;
use Clavia\Domain\Identity\Event\UserCreated;
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Provisioning\ProvisionedAccount;
use Clavia\Domain\Provisioning\ProvisionedAccountRepository;
use Clavia\Domain\Provisioning\ScimUser;
use Clavia\Domain\Provisioning\SubjectAttribute;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;

/**
 * `POST /scim/v2/Users` (RFC 7644 §3.3; docs/design/scim-provisioning.md §5.3): the account a
 * directory creates in the connection its token reaches.
 *
 * In one transaction: the account (no password, active as the directory says, its address verified
 * only when the token trusts the directory for addresses), its provisioned record, and, in an
 * enterprise connection, its external identity `(connection, subject)` from the attribute the token
 * names, so the person's first sign-in finds this account instead of making another. `UserCreated`
 * names the token as the actor. Each unique attribute is the storage's to decide: a taken address,
 * `userName`, `externalId` or subject leaves nothing behind.
 */
final readonly class CreateScimUser
{
    public function __construct(
        private UserRepository $users,
        private ProvisionedAccountRepository $accounts,
        private ExternalIdentityRepository $identities,
        private TransactionManager $transactions,
        private RandomSource $random,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws InvalidValue When the resource has no address, or an enterprise connection's account
     *                      lacks the attribute that names its subject.
     */
    public function __invoke(ProvisioningCaller $caller, ScimUser $resource): ProvisionedUser|AttributeTaken
    {
        $token = $caller->token;
        $connection = $caller->connection;
        $subject = null;
        if ($connection->isExternal()) {
            $subject = $resource->subject($token->subjectAttribute) ?? throw new InvalidValue(sprintf(
                "'%s' is required: it names the person to the connection they sign in through.",
                $token->subjectAttribute->value,
            ));
        }
        $now = $this->clock->now();
        $user = User::provision(
            UserId::generate($this->random),
            $resource->address(),
            $token->addressesTrusted,
            $resource->active,
            $resource->profile(),
            $connection->name,
            $now,
        );
        $account = ProvisionedAccount::provision($user->id, $connection->name, $resource, $token->id, $now);

        /** @var 'emails'|'account'|'subject' $step */
        $step = 'emails';
        try {
            $this->transactions->transactional(function () use ($user, $account, $subject, $now, &$step): void {
                $this->users->save($user);
                $step = 'account';
                $this->accounts->add($account);
                if ($subject !== null) {
                    $step = 'subject';
                    $this->identities->add(
                        ExternalIdentity::provision($account->connection, $subject, $user->id, $user->email, $now),
                    );
                }
                $this->events->dispatch(new UserCreated($user));
            });
        } catch (AlreadyExists $conflict) {
            return new AttributeTaken(match ($step) {
                'emails' => 'emails',
                'account' => $conflict->getMessage() === ProvisionedAccountRepository::EXTERNAL_ID_TAKEN
                    ? 'externalId'
                    : 'userName',
                'subject' => $token->subjectAttribute === SubjectAttribute::ExternalId ? 'externalId' : 'userName',
            });
        }

        return new ProvisionedUser($user, $account);
    }
}
