<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Application\Authentication\Passkey\AssertionOptions;
use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Open a ceremony for the passkey that will answer a second-factor challenge
 * (docs/design/passkeys.md §6.3): bound to that challenge and its account, naming the account's
 * passkeys.
 *
 * Nothing when there is no challenge, or the account holds no passkey.
 */
final readonly class BeginPasskeySecondFactor
{
    /**
     * @param positive-int $ceremonyLifetimeSeconds `CLAVIA_WEBAUTHN_CEREMONY_LIFETIME`.
     */
    public function __construct(
        private MfaChallengeStore $challenges,
        private PasskeyRepository $passkeys,
        private WebAuthnChallengeStore $ceremonies,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private Clock $clock,
        private RelyingParty $relyingParty,
        private int $ceremonyLifetimeSeconds,
    ) {
    }

    /**
     * @param string $challenge The second-factor challenge's handle.
     */
    public function __invoke(#[\SensitiveParameter] string $challenge): ?AssertionOptions
    {
        if ($challenge === '') {
            return null;
        }
        $pending = $this->challenges->find($challenge);
        if ($pending === null) {
            return null;
        }
        $passkeys = $this->passkeys->ofUser($pending->userId);
        if ($passkeys === []) {
            return null;
        }

        $ceremony = WebAuthnChallenge::forSecondFactor(
            $this->random,
            $pending->userId,
            $challenge,
            $this->clock->now(),
            $this->ceremonyLifetimeSeconds,
        );
        $handle = $this->secrets->token();
        $this->ceremonies->open($handle, $ceremony, $this->ceremonyLifetimeSeconds);

        return new AssertionOptions($handle, $this->relyingParty, $ceremony, $passkeys, $this->ceremonyLifetimeSeconds);
    }
}
