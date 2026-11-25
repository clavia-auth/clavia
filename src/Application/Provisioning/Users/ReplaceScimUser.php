<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning\Users;

use Clavia\Application\Authentication\SignOutEverywhere;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Provisioning\ProvisioningCaller;
use Clavia\Domain\Identity\Event\UserChanged;
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Provisioning\ProvisionedAccountRepository;
use Clavia\Domain\Provisioning\ScimUser;
use Clavia\Domain\Provisioning\SubjectAttribute;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `PUT /scim/v2/Users/{id}` (RFC 7644 §3.5.1; docs/design/scim-provisioning.md §5.3), and what a
 * `PATCH` becomes once applied ({@see PatchScimUser}): the account made to be the resource sent.
 *
 * An optional attribute left out is cleared; the address follows the primary email, unverified
 * unless the token trusts the directory for addresses; `userName` and `externalId` move with the
 * record, and, in an enterprise connection, the identity follows the subject attribute. One
 * transaction, the storage deciding every uniqueness, and `UserChanged` naming what changed.
 *
 * `active: false` does what an operator's deactivation does: every session ends, with back-channel
 * logout ({@see SignOutEverywhere}), and refresh and access tokens stop where they are next checked
 * against the account. `active: true` reactivates.
 */
final readonly class ReplaceScimUser
{
    public function __construct(
        private ReadScimUsers $read,
        private UserRepository $users,
        private ProvisionedAccountRepository $accounts,
        private ExternalIdentityRepository $identities,
        private TransactionManager $transactions,
        private SignOutEverywhere $signOut,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @param list<string>|null $ifMatch The versions `If-Match` names; null without one.
     *
     * @return ProvisionedUser|AttributeTaken|VersionMismatch|null Null when the connection has no such account.
     *
     * @throws InvalidValue When the resource has no address, or an enterprise connection's lacks its subject.
     */
    public function __invoke(
        ProvisioningCaller $caller,
        string $id,
        ScimUser $resource,
        ?array $ifMatch = null,
    ): ProvisionedUser|AttributeTaken|VersionMismatch|null {
        $current = $this->read->find($caller, $id);
        if ($current === null) {
            return null;
        }
        if (! $current->isAt($ifMatch)) {
            return new VersionMismatch();
        }
        $token = $caller->token;
        $user = $current->user;
        $before = ScimUser::of($user, $current->account);
        $subject = null;
        if ($caller->connection->isExternal()) {
            $subject = $resource->subject($token->subjectAttribute) ?? throw new InvalidValue(sprintf(
                "'%s' is required: it names the person to the connection they sign in through.",
                $token->subjectAttribute->value,
            ));
        }
        $now = $this->clock->now();
        $changed = [];
        $address = $resource->address();
        if ($address !== $user->email) {
            $user->changeEmail($address, $now);
            $user->recordEmailVerification($token->addressesTrusted, $now);
            $changed[] = 'email';
        }
        $profile = $resource->profile($user->profile()->picture?->value);
        if (! $profile->equals($user->profile())) {
            $user->changeProfile($profile, $now);
            $changed[] = 'profile';
        }
        $deactivated = ! $resource->active && $user->isActive();
        if ($resource->active !== $user->isActive()) {
            $resource->active ? $user->activate($now) : $user->deactivate($now);
            $changed[] = 'is_active';
        }
        $account = $current->account->changedTo($resource, $now);
        if ($account->userName !== $current->account->userName) {
            $changed[] = 'user_name';
        }
        if ($account->externalId !== $current->account->externalId) {
            $changed[] = 'external_id';
        }
        $movedSubject = $subject !== null && $subject !== $before->subject($token->subjectAttribute)
            ? $subject
            : null;

        /** @var 'emails'|'account'|'subject' $step */
        $step = 'emails';
        try {
            $this->transactions->transactional(
                function () use ($user, $account, $current, $movedSubject, $changed, $deactivated, $now, &$step): void {
                    $this->users->save($user);
                    $step = 'account';
                    if ($account !== $current->account) {
                        $this->accounts->save($account);
                    }
                    if ($movedSubject !== null) {
                        $step = 'subject';
                        $this->identities->unlink($user->id, $account->connection);
                        $this->identities->add(ExternalIdentity::provision(
                            $account->connection,
                            $movedSubject,
                            $user->id,
                            $user->email,
                            $now,
                        ));
                    }
                    if ($changed !== []) {
                        $this->events->dispatch(new UserChanged($user->id, $changed, $deactivated));
                    }
                },
            );
        } catch (AlreadyExists $conflict) {
            return new AttributeTaken(match ($step) {
                'emails' => 'emails',
                'account' => $conflict->getMessage() === ProvisionedAccountRepository::EXTERNAL_ID_TAKEN
                    ? 'externalId'
                    : 'userName',
                'subject' => $token->subjectAttribute === SubjectAttribute::ExternalId ? 'externalId' : 'userName',
            });
        }
        // A leaver is signed out everywhere, and the applications told, once the change is committed.
        if ($deactivated) {
            ($this->signOut)($user->id);
        }

        return new ProvisionedUser($user, $account);
    }
}
