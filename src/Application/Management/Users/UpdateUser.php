<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Identity\PasswordPolicy;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `PATCH /api/v1/users/{user_id}`.
 *
 * A new address is unverified unless the same request says otherwise. Deactivating an
 * account takes effect on its next request: sessions and tokens are re-checked against
 * the account wherever they are used.
 */
final readonly class UpdateUser
{
    public function __construct(
        private UserRepository $users,
        private PasswordHasher $hasher,
        private Clock $clock,
        private MfaFactorRepository $factors,
    ) {
    }

    /**
     * @throws NotFound
     * @throws InvalidValue  When a new value is not acceptable.
     * @throws AlreadyExists When another account uses the new address.
     */
    public function __invoke(UserId $id, UserChanges $changes): ManagedUser
    {
        $user = $this->users->find($id) ?? throw NotFound::of('user');
        $now = $this->clock->now();

        if ($changes->email !== null) {
            $user->changeEmail($changes->email, $now);
        }
        if ($changes->emailVerified !== null) {
            $user->recordEmailVerification($changes->emailVerified, $now);
        }
        if ($changes->password !== null) {
            $user->changePassword($this->hasher->hash(PasswordPolicy::accept($changes->password)), $now);
        }
        if ($changes->isActive === true) {
            $user->activate($now);
        } elseif ($changes->isActive === false) {
            $user->deactivate($now);
        }
        if ($changes->profile !== []) {
            $user->changeProfile(ProfileFields::apply($user->profile(), $changes->profile), $now);
        }

        $this->users->save($user);

        return new ManagedUser($user, $this->factors->find($id)?->isConfirmed() ?? false);
    }
}
