<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Configuration\Settings;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class CompleteFirstFactorFactory
{
    public function __invoke(ContainerInterface $container): CompleteFirstFactor
    {
        /** @var Sessions $sessions */
        $sessions = $container->get(Sessions::class);
        /** @var MfaFactorRepository $factors */
        $factors = $container->get(MfaFactorRepository::class);
        /** @var MfaChallengeStore $challenges */
        $challenges = $container->get(MfaChallengeStore::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $challengeLifetime = $settings->mfaChallengeLifetime;
        assert($challengeLifetime > 0);

        return new CompleteFirstFactor($sessions, $factors, $challenges, $secrets, $challengeLifetime);
    }
}
