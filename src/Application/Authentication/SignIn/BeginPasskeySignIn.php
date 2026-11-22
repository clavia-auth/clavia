<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\SignIn;

use Clavia\Application\Authentication\Passkey\AssertionOptions;
use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Open the ceremony the login page offers a passkey with (docs/design/passkeys.md §6.2): no
 * account named (`allowCredentials` empty, so any discoverable passkey answers), the person
 * verified, and the challenge bound to the authorization request the page holds, so a response
 * answers that request and no other.
 *
 * A page reached directly holds no request; its ceremony is bound to itself — to its own
 * handle — which still makes it answerable once, by the browser that holds it. Whether the page
 * offers a passkey at all is the login page's to say (`SignInMethods::$passkey`).
 */
final readonly class BeginPasskeySignIn
{
    /**
     * @param positive-int $ceremonyLifetimeSeconds `CLAVIA_WEBAUTHN_CEREMONY_LIFETIME`.
     */
    public function __construct(
        private WebAuthnChallengeStore $ceremonies,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private Clock $clock,
        private RelyingParty $relyingParty,
        private int $ceremonyLifetimeSeconds,
    ) {
    }

    /**
     * @param string|null $loginState The login page's handle, if it holds a request.
     */
    public function __invoke(#[\SensitiveParameter] ?string $loginState): AssertionOptions
    {
        $handle = $this->secrets->token();
        $ceremony = WebAuthnChallenge::forSignIn(
            $this->random,
            $loginState === null || $loginState === '' ? $handle : $loginState,
            $this->clock->now(),
            $this->ceremonyLifetimeSeconds,
        );
        $this->ceremonies->open($handle, $ceremony, $this->ceremonyLifetimeSeconds);

        return new AssertionOptions($handle, $this->relyingParty, $ceremony, [], $this->ceremonyLifetimeSeconds);
    }
}
