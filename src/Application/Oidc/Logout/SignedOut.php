<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc\Logout;

/**
 * Where the browser goes now, and whether a session was ended on the way.
 */
final readonly class SignedOut
{
    /**
     * @param string $location      A registered post-logout redirect URI with `state`, or this
     *                              server's login page.
     * @param bool   $sessionEnded  False when there was no session, or nothing proved the request.
     */
    public function __construct(
        public string $location,
        public bool $sessionEnded,
    ) {
    }
}
