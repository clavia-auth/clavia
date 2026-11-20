<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\Identity\ProviderName;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;

/**
 * An external identity provider Clavia signs people in through — Clavia being, for
 * once, the OAuth 2.0 client (RFC 6749 §4.1).
 *
 * The provider's endpoints, scopes and "who is this?" call are the adapter's; the use
 * cases decide everything else: the `state`, the PKCE pair (sent to every provider:
 * one that does not implement RFC 7636 ignores it), the redirect URI, and what the
 * answer means for an account.
 */
interface IdentityProvider
{
    public function name(): ProviderName;

    /** What the login page calls it: "Continue with {label}". */
    public function label(): string;

    /**
     * Where to send the browser: the provider's authorization endpoint with
     * `response_type=code`, the client id, `$redirectUri`, the scope, `$state` and the
     * S256 `$challenge`.
     *
     * @param non-empty-string $state
     */
    public function authorizationUrl(string $redirectUri, string $state, CodeChallenge $challenge): string;

    /**
     * Exchange the code, server to server and with the client secret, and ask the
     * provider who signed in.
     *
     * @throws IdentityProviderFailed Whenever that does not give a usable answer — the reason
     *                                is logged by the adapter, never shown.
     */
    public function identify(
        #[\SensitiveParameter] string $code,
        string $redirectUri,
        CodeVerifier $verifier,
    ): AssertedIdentity;
}
