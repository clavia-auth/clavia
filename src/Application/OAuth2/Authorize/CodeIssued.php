<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Authorize;

/**
 * The request was granted: send the browser back to the client with a code
 * (RFC 6749 §4.1.2).
 */
final readonly class CodeIssued implements AuthorizationOutcome
{
    /**
     * @param string      $redirectUri The client's validated redirect URI.
     * @param string      $code        The single-use authorization code — shown once, here.
     * @param string|null $state       The client's `state`, returned untouched: it is its CSRF defence.
     */
    public function __construct(
        public string $redirectUri,
        #[\SensitiveParameter] public string $code,
        public ?string $state,
    ) {
    }
}
