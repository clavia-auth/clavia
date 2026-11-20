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
 * The request is valid but nobody is signed in: send the browser to the login page.
 *
 * Deliberately not an error for the client. OpenID Connect only defines
 * `login_required` as a response to `prompt=none`; anyone else is simply asked to
 * sign in and then brought back.
 */
final readonly class LoginRequired implements AuthorizationOutcome
{
    /**
     * @param non-empty-string $loginState The opaque handle under which this request is parked.
     */
    public function __construct(public string $loginState)
    {
    }
}
