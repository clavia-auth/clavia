<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Application\Management\Connections\ReadConnections;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\Event\UserCreated;
use Clavia\Domain\Identity\PasswordPolicy;
use Clavia\Domain\Identity\Profile;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;

/**
 * `POST /api/v1/users`: an account, in a pool — the default one unless another is named.
 * A password, when given, is checked against the policy, hashed on the way in with the same
 * primitive the login page verifies against, and never returned. Without one the account is
 * an invitation waiting to be sent: password sign-in fails like any other, and the person
 * chooses a password from the link of {@see SendPasswordLink}. An external connection's accounts are made by signing in
 * through it, not here.
 */
final readonly class CreateUser
{
    public function __construct(
        private UserRepository $users,
        private PasswordHasher $hasher,
        private RandomSource $random,
        private Clock $clock,
        private ConnectionRepository $connections,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws InvalidValue  When the address, a given password or a profile field is not acceptable, or
     *                       the connection is not a pool.
     * @throws NotFound      When the connection does not exist.
     * @throws AlreadyExists When another account in the pool uses the address.
     */
    public function __invoke(NewUser $new): ManagedUser
    {
        $pool = $new->connection === null
            ? ConnectionName::defaultPool()
            : ReadConnections::find($this->connections, $new->connection)->name;
        if (! ($this->connections->find($pool)?->isDatabase() ?? false)) {
            throw new InvalidValue(sprintf(
                "Accounts are created in a pool; '%s' is not one. Its accounts are made by signing in through it.",
                $pool->value,
            ));
        }

        $now = $this->clock->now();
        $profile = ProfileFields::apply(Profile::empty(), $new->profile);

        $user = User::register(
            UserId::generate($this->random),
            $new->email,
            $new->password === null ? null : $this->hasher->hash(PasswordPolicy::accept($new->password)),
            $now,
            $pool,
        );
        $user->changeProfile($profile, $now);
        $user->recordEmailVerification($new->emailVerified, $now);
        if (! $new->isActive) {
            $user->deactivate($now);
        }

        $this->users->save($user);
        $this->events->dispatch(new UserCreated($user));

        // A new account has no second factor: enrolling one is something its holder does.
        return new ManagedUser($user, false);
    }
}
