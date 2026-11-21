<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\Connections\ReadConnections;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\Event\IdentityUnlinked;
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;

/**
 * `DELETE /api/v1/users/{user_id}/identities/{connection}`: detach the account's identity
 * at an external provider. Signing in through that provider again makes a new account,
 * or links by address as a first sign-in would.
 *
 * Refused when it is the account's only way in — no password it could use, no other
 * identity: an account nobody can sign in to is not what the operator asked for. A
 * password counts only for an account in a pool, the one place a password is checked.
 */
final readonly class UnlinkIdentity
{
    public function __construct(
        private UserRepository $users,
        private ExternalIdentityRepository $identities,
        private ConnectionRepository $connections,
        private TransactionManager $transactions,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound When the user, the connection or a linked identity through it does not exist.
     * @throws Conflict When it is the account's only way in.
     */
    public function __invoke(UserId $userId, string $connection): void
    {
        $user = $this->users->find($userId) ?? throw NotFound::of('user');
        $provider = ReadConnections::find($this->connections, $connection)->name;

        $this->transactions->transactional(function () use ($user, $provider): void {
            $identities = $this->identities->ofUser($user->id);
            $through = array_filter(
                $identities,
                static fn (ExternalIdentity $identity): bool => $identity->provider->equals($provider),
            );
            if ($through === []) {
                throw NotFound::of('identity');
            }

            $hasPassword = $user->passwordHash() !== null
                && ($this->connections->find($user->connection)?->isDatabase() ?? false);
            if (! $hasPassword && count($through) === count($identities)) {
                throw new Conflict(
                    "This identity is the account's only way in: it has no password and nothing else linked. "
                    . 'Delete the account instead, or give it another way in first.',
                );
            }

            $this->identities->unlink($user->id, $provider);
            $this->events->dispatch(new IdentityUnlinked($user->id, $provider));
        });
    }
}
