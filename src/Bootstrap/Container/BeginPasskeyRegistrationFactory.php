<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Passkey\BeginPasskeyRegistration;
use Clavia\Application\Authentication\Passkey\RecentSignIn;
use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Configuration\Settings;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class BeginPasskeyRegistrationFactory
{
    public function __invoke(ContainerInterface $container): BeginPasskeyRegistration
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var PasskeyRepository $passkeys */
        $passkeys = $container->get(PasskeyRepository::class);
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
        /** @var RecentSignIn $recentSignIn */
        $recentSignIn = $container->get(RecentSignIn::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $lifetime = $settings->webauthnCeremonyLifetime;
        $max = $settings->passkeyMaxPerUser;
        assert($lifetime > 0 && $max > 0);

        return new BeginPasskeyRegistration(
            $users,
            $passkeys,
            $ceremonies,
            $secrets,
            $random,
            $clock,
            $relyingParty,
            $recentSignIn,
            $lifetime,
            $max,
        );
    }
}
