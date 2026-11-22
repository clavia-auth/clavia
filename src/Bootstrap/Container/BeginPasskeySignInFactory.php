<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\SignIn\BeginPasskeySignIn;
use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Configuration\Settings;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class BeginPasskeySignInFactory
{
    public function __invoke(ContainerInterface $container): BeginPasskeySignIn
    {
        /** @var WebAuthnChallengeStore $ceremonies */
        $ceremonies = $container->get(WebAuthnChallengeStore::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var RelyingParty $relyingParty */
        $relyingParty = $container->get(RelyingParty::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $lifetime = $settings->webauthnCeremonyLifetime;
        assert($lifetime > 0);

        return new BeginPasskeySignIn($ceremonies, $secrets, $random, $clock, $relyingParty, $lifetime);
    }
}
