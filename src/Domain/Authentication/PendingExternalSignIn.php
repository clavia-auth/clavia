<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\ProviderName;
use Clavia\Domain\OAuth2\CodeVerifier;

/**
 * A sign-in sent out to an external provider and not back yet.
 *
 * Clavia is the OAuth 2.0 client here, and holds itself to what it demands of its own
 * clients: the browser carries an opaque `state` handle — in the provider's redirect
 * and in a cookie — while what the handle stands for stays server-side: where to go
 * afterwards, and the PKCE verifier (RFC 7636) that only this server may present.
 */
final readonly class PendingExternalSignIn
{
    /**
     * Long enough to authenticate at the provider — which may ask for its own second
     * factor — short enough that an abandoned attempt does not linger.
     */
    public const int LIFETIME_SECONDS = 600;

    /**
     * @param string        $nextUrl    Validated as a {@see LocalPath} when the sign-in started.
     * @param ClientId|null $clientId   The application the sign-in is for, if it came from one.
     * @param string|null   $loginState The login page's handle, forgotten once the sign-in completes.
     */
    public function __construct(
        public ProviderName $provider,
        public CodeVerifier $codeVerifier,
        public string $nextUrl,
        public ?ClientId $clientId,
        public ?string $loginState,
    ) {
    }
}
