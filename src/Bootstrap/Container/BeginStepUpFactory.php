<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Mfa\BeginStepUp;
use Clavia\Application\Authentication\Mfa\SecondFactors;
use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class BeginStepUpFactory
{
    public function __invoke(ContainerInterface $container): BeginStepUp
    {
        /** @var MfaChallengeStore $challenges */
        $challenges = $container->get(MfaChallengeStore::class);
        /** @var SecondFactors $secondFactors */
        $secondFactors = $container->get(SecondFactors::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $lifetime = $settings->mfaChallengeLifetime;
        assert($lifetime > 0);

        return new BeginStepUp($challenges, $secondFactors, $secrets, $lifetime);
    }
}
