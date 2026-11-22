<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Passkey\CompletePasskeyRegistration;
use Clavia\Application\Authentication\Passkey\RecentSignIn;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\PasskeyVerifier;
use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Configuration\Settings;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Psr\Container\ContainerInterface;

final class CompletePasskeyRegistrationFactory
{
    public function __invoke(ContainerInterface $container): CompletePasskeyRegistration
    {
        /** @var WebAuthnChallengeStore $ceremonies */
        $ceremonies = $container->get(WebAuthnChallengeStore::class);
        /** @var PasskeyVerifier $verifier */
        $verifier = $container->get(PasskeyVerifier::class);
        /** @var PasskeyRepository $passkeys */
        $passkeys = $container->get(PasskeyRepository::class);
        /** @var MfaFactorRepository $factors */
        $factors = $container->get(MfaFactorRepository::class);
        /** @var RecoveryCodeRepository $recoveryCodes */
        $recoveryCodes = $container->get(RecoveryCodeRepository::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);
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
        $max = $settings->passkeyMaxPerUser;
        $codes = $settings->mfaRecoveryCodeCount;
        assert($max > 0 && $codes > 0);

        return new CompletePasskeyRegistration(
            $ceremonies,
            $verifier,
            $passkeys,
            $factors,
            $recoveryCodes,
            $transactions,
            $events,
            $random,
            $clock,
            $relyingParty,
            $recentSignIn,
            $max,
            $codes,
        );
    }
}
