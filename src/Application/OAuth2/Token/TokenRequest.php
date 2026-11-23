<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Token;

use Clavia\Application\OAuth2\ClientAuthentication\ClientCredentials;
use Clavia\Application\OAuth2\RequestParameters;

/**
 * A request to the token endpoint (RFC 6749 §3.2), as received.
 */
final readonly class TokenRequest
{
    /**
     * @param RequestParameters $parameters          The form body, unvalidated.
     * @param string|null       $authorizationHeader The raw `Authorization` header, when there is one.
     * @param string            $clientAddress       The address the request came from, as the web server saw it.
     * @param list<string>      $dpopProofs          Every `DPoP` header it carried (RFC 9449 §4.1).
     */
    public function __construct(
        public RequestParameters $parameters,
        #[\SensitiveParameter] public ?string $authorizationHeader,
        public string $clientAddress,
        public array $dpopProofs = [],
    ) {
    }

    public function credentials(): ClientCredentials
    {
        return new ClientCredentials($this->authorizationHeader, $this->parameters, $this->clientAddress);
    }
}
