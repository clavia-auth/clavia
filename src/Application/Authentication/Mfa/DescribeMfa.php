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
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
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
        private PasskeyRepository $passkeys,
        private bool $passkeysEnabled,
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
        $passkeys = $this->passkeysEnabled ? $this->passkeys->countOf($userId) : null;
        $codes = $enabled || ($passkeys ?? 0) > 0 ? $this->recoveryCodes->unusedCount($userId) : 0;

        return new MfaStatus($user->email, $enabled, $codes, $passkeys);
    }
}
