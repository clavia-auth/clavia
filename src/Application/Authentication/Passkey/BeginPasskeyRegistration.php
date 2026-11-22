<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Open a ceremony to register a passkey on the session's account (docs/design/passkeys.md §6.1):
 * the options the browser needs, behind a handle the browser keeps.
 *
 * Refused when the session signed in too long ago, and when the account already holds as many
 * passkeys as it may. Nothing is stored about the passkey until the response verifies.
 */
final readonly class BeginPasskeyRegistration
{
    /**
     * @param positive-int $ceremonyLifetimeSeconds `CLAVIA_WEBAUTHN_CEREMONY_LIFETIME`.
     * @param positive-int $maxPerUser              `CLAVIA_PASSKEY_MAX_PER_USER`.
     */
    public function __construct(
        private UserRepository $users,
        private PasskeyRepository $passkeys,
        private WebAuthnChallengeStore $ceremonies,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private Clock $clock,
        private RelyingParty $relyingParty,
        private RecentSignIn $recentSignIn,
        private int $ceremonyLifetimeSeconds,
        private int $maxPerUser,
    ) {
    }

    /**
     * @return RegistrationOptions|SignInAgain|PasskeyLimitReached|null Null when the account is gone.
     */
    public function __invoke(Session $session): RegistrationOptions|SignInAgain|PasskeyLimitReached|null
    {
        if (! $this->recentSignIn->allows($session)) {
            return new SignInAgain();
        }
        $user = $this->users->find($session->userId);
        if ($user === null || ! $user->isActive()) {
            return null;
        }
        $existing = $this->passkeys->ofUser($user->id);
        if (count($existing) >= $this->maxPerUser) {
            return new PasskeyLimitReached($this->maxPerUser);
        }

        $challenge = WebAuthnChallenge::forRegistration(
            $this->random,
            $user->id,
            $this->clock->now(),
            $this->ceremonyLifetimeSeconds,
        );
        $handle = $this->secrets->token();
        $this->ceremonies->open($handle, $challenge, $this->ceremonyLifetimeSeconds);

        return new RegistrationOptions(
            $handle,
            $this->relyingParty,
            $challenge,
            $user->email,
            $user->profile()->name ?? $user->email,
            $existing,
            $this->ceremonyLifetimeSeconds,
        );
    }
}
