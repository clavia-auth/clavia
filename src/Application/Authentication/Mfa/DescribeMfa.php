<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;

/**
 * What the two-factor settings page says about an account.
 */
final readonly class DescribeMfa
{
    public function __construct(
        private UserRepository $users,
        private MfaFactorRepository $factors,
        private RecoveryCodeRepository $recoveryCodes,
    ) {
    }

    /** Null when the account no longer exists. */
    public function __invoke(UserId $userId): ?MfaStatus
    {
        $user = $this->users->find($userId);
        if ($user === null) {
            return null;
        }
        $enabled = $this->factors->find($userId)?->isConfirmed() ?? false;

        return new MfaStatus($user->email, $enabled, $enabled ? $this->recoveryCodes->unusedCount($userId) : 0);
    }
}
