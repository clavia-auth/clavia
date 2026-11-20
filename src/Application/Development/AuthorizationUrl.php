<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Development;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\CodeVerifier;

/**
 * An authorization request ready to be opened, and what is needed to finish it.
 */
final readonly class AuthorizationUrl
{
    /**
     * @param CodeVerifier          $verifier   The secret half of the PKCE pair, for the token request.
     * @param array<string, string> $parameters The query parameters of the authorization request.
     */
    public function __construct(
        public ClientId $clientId,
        public string $redirectUri,
        public CodeVerifier $verifier,
        public array $parameters,
    ) {
    }
}
