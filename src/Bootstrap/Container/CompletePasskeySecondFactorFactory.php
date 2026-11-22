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
use Clavia\Application\Authentication\Mfa\CompletePasskeySecondFactor;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Application\Port\PasskeyVerifier;
use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Configuration\Settings;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class CompletePasskeySecondFactorFactory
{
    public function __invoke(ContainerInterface $container): CompletePasskeySecondFactor
    {
        /** @var MfaChallengeStore $challenges */
        $challenges = $container->get(MfaChallengeStore::class);
        /** @var WebAuthnChallengeStore $ceremonies */
        $ceremonies = $container->get(WebAuthnChallengeStore::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var PasskeyRepository $passkeys */
        $passkeys = $container->get(PasskeyRepository::class);
        /** @var PasskeyVerifier $verifier */
        $verifier = $container->get(PasskeyVerifier::class);
        /** @var LoginThrottle $throttle */
        $throttle = $container->get(LoginThrottle::class);
        /** @var Sessions $sessions */
        $sessions = $container->get(Sessions::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var RelyingParty $relyingParty */
        $relyingParty = $container->get(RelyingParty::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $maxAttempts = $settings->mfaMaxAttempts;
        assert($maxAttempts > 0);

        return new CompletePasskeySecondFactor(
            $challenges,
            $ceremonies,
            $users,
            $passkeys,
            $verifier,
            $throttle,
            $sessions,
            $clock,
            $relyingParty,
            $maxAttempts,
            $events,
        );
    }
}
