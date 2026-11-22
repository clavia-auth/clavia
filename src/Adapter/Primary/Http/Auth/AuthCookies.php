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
use Clavia\Domain\Authentication\PendingExternalSignIn;

/**
 * The cookies of the auth surface: their names, paths and lifetimes in one place, so a
 * cookie is always deleted with the attributes it was set with.
 *
 * - **Session** (`CLAVIA_SESSION_COOKIE_NAME`, path `/`): the identifier of the browser
 *   session. Lasts the absolute session lifetime; the server ends it sooner when idle.
 * - **CSRF** (`clavia_csrf`, path `/auth`): the double-submit token. Nothing outside
 *   `/auth` reads it, and it only has to outlast one form.
 * - **Second-factor challenge** (`clavia_mfa`, path `/auth`): the handle of a sign-in
 *   waiting for its second factor. Lasts as long as the challenge may; deleted when it
 *   ends, either way.
 * - **Passwordless code** (`clavia_passwordless`, path `/auth`): the handle of a sign-in
 *   waiting for the code sent by email. The code answers only the challenge this cookie
 *   names, so it works in the browser that asked and nowhere else. Lasts as long as the
 *   code does.
 * - **External sign-in** (`clavia_external_state`, path `/auth`): the `state` of a sign-in
 *   sent out to an external provider. The provider echoes the same value; the cookie is
 *   what proves the browser coming back is the one that left. `SameSite=Lax` still sends
 *   it on the provider's top-level redirect back.
 * - **WebAuthn ceremony** (`clavia_webauthn`, path `/auth`): the handle of a passkey ceremony in
 *   progress. The response is checked against the ceremony this cookie names, so it answers in
 *   the browser that asked. Lasts as long as the ceremony may; deleted when it is answered.
 * - **Theme** (`clavia_theme`, path `/`): the colour scheme; absent means "follow the
 *   system". Read by nothing but the page's `data-theme` attribute.
 */
final readonly class AuthCookies
{
    public const string CSRF = 'clavia_csrf';

    public const string CSRF_PATH = '/auth';

    public const int CSRF_LIFETIME = 3600;

    public const string MFA_CHALLENGE = 'clavia_mfa';

    public const string MFA_CHALLENGE_PATH = '/auth';

    public const string PASSWORDLESS = 'clavia_passwordless';

    public const string PASSWORDLESS_PATH = '/auth';

    public const string EXTERNAL_SIGN_IN = 'clavia_external_state';

    public const string EXTERNAL_SIGN_IN_PATH = '/auth';

    public const string WEBAUTHN = 'clavia_webauthn';

    public const string WEBAUTHN_PATH = '/auth';

    public const string THEME = PageRenderer::THEME_COOKIE;

    public const int THEME_LIFETIME = 365 * 24 * 3600;

    /** The colour schemes a person can force; anything else follows the system. */
    public const array THEMES = PageRenderer::THEMES;

    /**
     * @param non-empty-string $sessionCookieName
     * @param positive-int     $sessionLifetime   The absolute session lifetime, in seconds.
     * @param bool             $secure            Whether cookies carry `Secure`; false only in development.
     * @param positive-int     $mfaChallengeLifetime How long the second step of a sign-in may take.
     * @param positive-int     $passwordlessCodeLifetime How long an emailed code stays valid.
     * @param positive-int     $webauthnCeremonyLifetime How long a passkey ceremony may take.
     */
    public function __construct(
        public string $sessionCookieName,
        private int $sessionLifetime,
        private bool $secure,
        private int $mfaChallengeLifetime = 300,
        private int $passwordlessCodeLifetime = 600,
        private int $webauthnCeremonyLifetime = 300,
    ) {
    }

    public function webauthn(#[\SensitiveParameter] string $handle): SetCookie
    {
        return SetCookie::create(
            self::WEBAUTHN,
            $handle,
            $this->webauthnCeremonyLifetime,
            self::WEBAUTHN_PATH,
            $this->secure,
        );
    }

    public function expireWebAuthn(): SetCookie
    {
        return SetCookie::expire(self::WEBAUTHN, self::WEBAUTHN_PATH, $this->secure);
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

    public function mfaChallenge(#[\SensitiveParameter] string $handle): SetCookie
    {
        return SetCookie::create(
            self::MFA_CHALLENGE,
            $handle,
            $this->mfaChallengeLifetime,
            self::MFA_CHALLENGE_PATH,
            $this->secure,
        );
    }

    public function expireMfaChallenge(): SetCookie
    {
        return SetCookie::expire(self::MFA_CHALLENGE, self::MFA_CHALLENGE_PATH, $this->secure);
    }

    public function passwordless(#[\SensitiveParameter] string $handle): SetCookie
    {
        return SetCookie::create(
            self::PASSWORDLESS,
            $handle,
            $this->passwordlessCodeLifetime,
            self::PASSWORDLESS_PATH,
            $this->secure,
        );
    }

    public function expirePasswordless(): SetCookie
    {
        return SetCookie::expire(self::PASSWORDLESS, self::PASSWORDLESS_PATH, $this->secure);
    }

    public function externalSignIn(#[\SensitiveParameter] string $state): SetCookie
    {
        return SetCookie::create(
            self::EXTERNAL_SIGN_IN,
            $state,
            PendingExternalSignIn::LIFETIME_SECONDS,
            self::EXTERNAL_SIGN_IN_PATH,
            $this->secure,
        );
    }

    public function expireExternalSignIn(): SetCookie
    {
        return SetCookie::expire(self::EXTERNAL_SIGN_IN, self::EXTERNAL_SIGN_IN_PATH, $this->secure);
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
