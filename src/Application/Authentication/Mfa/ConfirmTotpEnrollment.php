<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCode;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;

/**
 * Prove the app produces the right codes, then turn the factor on and issue recovery
 * codes.
 *
 * Confirmation is what separates an enrolled factor from a scanned QR nobody kept: a
 * person who mistyped the seed would otherwise lock themselves out with an app that
 * never produces an accepted code. Recovery codes come only now, so a fallback is never
 * printed for a factor that was never switched on. All in one transaction, under the
 * factor's row lock: the confirming code's step is spent with it.
 */
final readonly class ConfirmTotpEnrollment
{
    /**
     * @param positive-int $recoveryCodeCount
     */
    public function __construct(
        private MfaFactorRepository $factors,
        private RecoveryCodeRepository $recoveryCodes,
        private TotpSeeds $seeds,
        private TransactionManager $transactions,
        private RandomSource $random,
        private Clock $clock,
        private int $recoveryCodeCount,
    ) {
    }

    /**
     * @return list<string>|null The recovery codes — the only time they exist in the clear —
     *                           or null when the code is wrong or nothing is pending.
     */
    public function __invoke(UserId $userId, #[\SensitiveParameter] string $code): ?array
    {
        return $this->transactions->transactional(function () use ($userId, $code): ?array {
            $factor = $this->factors->lockForVerification($userId);
            if ($factor === null || $factor->isConfirmed()) {
                return null;
            }

            $now = $this->clock->now();
            if (! $factor->accept($this->seeds->open($factor), $code, $now)) {
                return null;
            }
            $factor->confirm($now);
            $this->factors->save($factor);

            $codes = RecoveryCode::issue($this->random, $this->recoveryCodeCount);
            $this->recoveryCodes->replaceAll($userId, array_map(RecoveryCode::digest(...), $codes), $now);

            return $codes;
        });
    }
}
