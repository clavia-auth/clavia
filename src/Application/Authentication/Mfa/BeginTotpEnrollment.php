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
use Clavia\Domain\Authentication\Mfa\FactorAlreadyConfirmed;
use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;

/**
 * Generate a seed and stage a pending factor holding it, replacing an earlier attempt
 * that was never confirmed. Nothing is enforced until {@see ConfirmTotpEnrollment}.
 */
final readonly class BeginTotpEnrollment
{
    public function __construct(
        private UserRepository $users,
        private MfaFactorRepository $factors,
        private TotpSeeds $seeds,
        private TransactionManager $transactions,
        private RandomSource $random,
        private Clock $clock,
    ) {
    }

    /**
     * @return TotpEnrollment|null Null when the account no longer exists.
     *
     * @throws FactorAlreadyConfirmed
     */
    public function __invoke(UserId $userId): ?TotpEnrollment
    {
        $user = $this->users->find($userId);
        if ($user === null) {
            return null;
        }

        $secret = TotpSecret::generate($this->random);
        $sealed = $this->seeds->seal($userId, $secret);

        $this->transactions->transactional(function () use ($userId, $sealed): void {
            $factor = $this->factors->lockForVerification($userId);
            if ($factor === null) {
                $factor = MfaFactor::stage($userId, $sealed, $this->clock->now());
            } else {
                $factor->restage($sealed);
            }
            $this->factors->save($factor);
        });

        return $this->seeds->enrollment($secret, $user->email);
    }
}
