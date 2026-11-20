<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Application\Port\PasswordHasher;
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
 * `POST /api/v1/users`: an account with a password, hashed on the way in with the same
 * primitive the login page verifies against, and never returned.
 */
final readonly class CreateUser
{
    public function __construct(
        private UserRepository $users,
        private PasswordHasher $hasher,
        private RandomSource $random,
        private Clock $clock,
    ) {
    }

    /**
     * @throws InvalidValue  When the address, the password or a profile field is not acceptable.
     * @throws AlreadyExists When another account uses the address.
     */
    public function __invoke(NewUser $new): User
    {
        $now = $this->clock->now();
        $profile = ProfileFields::apply(Profile::empty(), $new->profile);

        $user = User::register(
            UserId::generate($this->random),
            $new->email,
            $this->hasher->hash(PasswordPolicy::accept($new->password)),
            $now,
        );
        $user->changeProfile($profile, $now);
        $user->recordEmailVerification($new->emailVerified, $now);
        if (! $new->isActive) {
            $user->deactivate($now);
        }

        $this->users->save($user);

        return $user;
    }
}
