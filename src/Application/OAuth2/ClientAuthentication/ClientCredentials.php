<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\ClientAuthentication;

use Clavia\Application\OAuth2\RequestParameters;

/**
 * What a client sent to identify itself at an endpoint, in whichever of the places
 * RFC 6749 §2.3 allows.
 */
final readonly class ClientCredentials
{
    /**
     * @param string|null       $authorizationHeader The raw `Authorization` header, when there is one.
     * @param RequestParameters $body                The form body, where `client_id` and
     *                                               `client_secret` may travel instead.
     * @param string            $clientAddress       Where the request came from, for {@see ClientFailureThrottle}.
     */
    public function __construct(
        #[\SensitiveParameter] public ?string $authorizationHeader,
        public RequestParameters $body,
        public string $clientAddress,
    ) {
    }
}
