<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Authorize;

use Clavia\Domain\OAuth2\OAuth2Error;

/**
 * The request was refused, and the client can be told: send the browser back to its
 * validated redirect URI with the error (RFC 6749 §4.1.2.1).
 */
final readonly class RequestRefused implements AuthorizationOutcome
{
    /**
     * @param string      $redirectUri The client's validated redirect URI.
     * @param string|null $state       Echoed whenever the request carried one: an error the client
     *                                 cannot tie to a request it made is one it cannot act on.
     */
    public function __construct(
        public string $redirectUri,
        public OAuth2Error $error,
        public ?string $state,
    ) {
    }
}
