<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\Mfa\CompleteSecondFactor;
use Clavia\Application\Authentication\Mfa\TotpSeeds;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Application\Port\TransactionManager;
use Clavia\Configuration\Settings;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class CompleteSecondFactorFactory
{
    public function __invoke(ContainerInterface $container): CompleteSecondFactor
    {
        /** @var MfaChallengeStore $challenges */
        $challenges = $container->get(MfaChallengeStore::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var MfaFactorRepository $factors */
        $factors = $container->get(MfaFactorRepository::class);
        /** @var RecoveryCodeRepository $recoveryCodes */
        $recoveryCodes = $container->get(RecoveryCodeRepository::class);
        /** @var TotpSeeds $seeds */
        $seeds = $container->get(TotpSeeds::class);
        /** @var LoginThrottle $throttle */
        $throttle = $container->get(LoginThrottle::class);
        /** @var Sessions $sessions */
        $sessions = $container->get(Sessions::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $maxAttempts = $settings->mfaMaxAttempts;
        assert($maxAttempts > 0);

        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new CompleteSecondFactor(
            $challenges,
            $users,
            $factors,
            $recoveryCodes,
            $seeds,
            $throttle,
            $sessions,
            $transactions,
            $clock,
            $maxAttempts,
            $events,
        );
    }
}
