<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The double-submit CSRF check of the auth pages.
 *
 * Every form carries a token that must equal one held in the browser's `clavia_csrf`
 * cookie. Both are set by this server; a cross-site page can post a form but can read
 * neither, so it cannot produce a matching pair. The token belongs to the browser, not
 * to a page or a session, which is what lets the login page work before anyone has a
 * session, and lets a second tab or the back button leave an open form valid.
 */
final class CsrfToken
{
    private function __construct()
    {
    }

    /**
     * Whether the submitted token matches any of the browser's CSRF cookies — a stale
     * extra cookie at another path must not lock a person out.
     */
    public static function isValid(ServerRequestInterface $request, #[\SensitiveParameter] ?string $submitted): bool
    {
        if ($submitted === null || $submitted === '') {
            return false;
        }

        return array_any(
            RequestCookies::all($request, AuthCookies::CSRF),
            static fn (string $held): bool => hash_equals($held, $submitted),
        );
    }
}
