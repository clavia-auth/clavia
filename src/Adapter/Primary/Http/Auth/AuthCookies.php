<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\PageRenderer;
use Clavia\Adapter\Primary\Http\Shared\SetCookie;

/**
 * The cookies of the auth surface: their names, paths and lifetimes in one place, so a
 * cookie is always deleted with the attributes it was set with.
 *
 * - **Session** (`CLAVIA_SESSION_COOKIE_NAME`, path `/`): the identifier of the browser
 *   session. Lasts the absolute session lifetime; the server ends it sooner when idle.
 * - **CSRF** (`clavia_csrf`, path `/auth`): the double-submit token. Nothing outside
 *   `/auth` reads it, and it only has to outlast one form.
 * - **Theme** (`clavia_theme`, path `/`): the colour scheme; absent means "follow the
 *   system". Read by nothing but the page's `data-theme` attribute.
 */
final readonly class AuthCookies
{
    public const string CSRF = 'clavia_csrf';

    public const string CSRF_PATH = '/auth';

    public const int CSRF_LIFETIME = 3600;

    public const string THEME = PageRenderer::THEME_COOKIE;

    public const int THEME_LIFETIME = 365 * 24 * 3600;

    /** The colour schemes a person can force; anything else follows the system. */
    public const array THEMES = PageRenderer::THEMES;

    /**
     * @param non-empty-string $sessionCookieName
     * @param positive-int     $sessionLifetime   The absolute session lifetime, in seconds.
     * @param bool             $secure            Whether cookies carry `Secure`; false only in development.
     */
    public function __construct(
        public string $sessionCookieName,
        private int $sessionLifetime,
        private bool $secure,
    ) {
    }

    public function session(#[\SensitiveParameter] string $sessionId): SetCookie
    {
        return SetCookie::create($this->sessionCookieName, $sessionId, $this->sessionLifetime, '/', $this->secure);
    }

    public function expireSession(): SetCookie
    {
        return SetCookie::expire($this->sessionCookieName, '/', $this->secure);
    }

    public function csrf(#[\SensitiveParameter] string $token): SetCookie
    {
        return SetCookie::create(self::CSRF, $token, self::CSRF_LIFETIME, self::CSRF_PATH, $this->secure);
    }

    public function expireCsrf(): SetCookie
    {
        return SetCookie::expire(self::CSRF, self::CSRF_PATH, $this->secure);
    }

    /**
     * A second CSRF cookie can only live at another path, and the only other path this
     * server is likely to have used is the root.
     */
    public function expireStrayCsrf(): SetCookie
    {
        return SetCookie::expire(self::CSRF, '/', $this->secure);
    }

    public function theme(string $theme): SetCookie
    {
        return SetCookie::create(self::THEME, $theme, self::THEME_LIFETIME, '/', $this->secure);
    }

    public function expireTheme(): SetCookie
    {
        return SetCookie::expire(self::THEME, '/', $this->secure);
    }
}
