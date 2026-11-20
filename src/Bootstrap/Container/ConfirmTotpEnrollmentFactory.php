<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Mfa\ConfirmTotpEnrollment;
use Clavia\Application\Authentication\Mfa\TotpSeeds;
use Clavia\Application\Port\TransactionManager;
use Clavia\Configuration\Settings;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Psr\Container\ContainerInterface;

final class ConfirmTotpEnrollmentFactory
{
    public function __invoke(ContainerInterface $container): ConfirmTotpEnrollment
    {
        /** @var MfaFactorRepository $factors */
        $factors = $container->get(MfaFactorRepository::class);
        /** @var RecoveryCodeRepository $recoveryCodes */
        $recoveryCodes = $container->get(RecoveryCodeRepository::class);
        /** @var TotpSeeds $seeds */
        $seeds = $container->get(TotpSeeds::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $recoveryCodeCount = $settings->mfaRecoveryCodeCount;
        assert($recoveryCodeCount > 0);

        return new ConfirmTotpEnrollment(
            $factors,
            $recoveryCodes,
            $seeds,
            $transactions,
            $random,
            $clock,
            $recoveryCodeCount,
        );
    }
}
