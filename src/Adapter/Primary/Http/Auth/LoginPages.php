<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\HtmlPage;
use Clavia\Adapter\Primary\Http\Shared\Message;
use Clavia\Application\Authentication\External\ExternalProviderOption;
use Clavia\Application\Authentication\LoginPage\SignInMethods;
use Clavia\Application\Authentication\Passkey\AssertionOptions;
use Fig\Http\Message\StatusCodeInterface;

/**
 * The view models of the login page, shared by the handler that shows it and the one
 * that re-shows it after a failed attempt — so the two cannot drift.
 */
final class LoginPages
{
    // Refusals other pages show too: keys of the catalogue, worded in the page's language through
    // Message::of() (docs/design/translated-sign-in-pages.md).
    public const string INVALID_CREDENTIALS = 'login.error.invalid_credentials';

    public const string EXPIRED_FORM = 'login.error.expired_form';

    public const string EXPIRED_REQUEST = 'login.error.expired_request';

    public const string PASSWORD_UNAVAILABLE = 'login.error.password_unavailable';

    public const string INVALID_EMAIL = 'login.error.invalid_email';

    public const string EMAIL_UNAVAILABLE = 'login.error.email_unavailable';

    public const string TOO_MANY_EMAILS = 'login.error.too_many_emails';

    public const string MAIL_UNAVAILABLE = 'login.error.mail_unavailable';

    private function __construct()
    {
    }

    /**
     * The sign-in form.
     *
     * @param list<string> $formOrigins
     * @param SignInMethods $methods    The password form and the email form when they are offered, the
     *                                  external connections as links below them.
     * @param AssertionOptions|null $passkey The ceremony a passkey answers, when one is offered: the page
     *                                  then loads `passkeys.js`, which offers it in the address field's
     *                                  autofill and behind a button.
     */
    public static function form(
        ?string $loginState,
        array $formOrigins,
        SignInMethods $methods,
        ?string $email = null,
        ?Message $error = null,
        int $status = StatusCodeInterface::STATUS_OK,
        ?AssertionOptions $passkey = null,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::login',
            title: Message::of('login.title'),
            heading: Message::of('login.title'),
            returnTo: self::address($loginState),
            variables: [
                'loginState' => $loginState ?? '',
                'email' => $email ?? '',
                'signedInAs' => null,
                'password' => $methods->password,
                'emailSignIn' => $methods->email,
                'providers' => array_map(
                    static fn (ExternalProviderOption $provider): array => [
                        'label' => $provider->label,
                        'href' => ($provider->saml ? '/auth/saml/' : '/auth/social/')
                            . rawurlencode($provider->name) . (
                            $loginState === null || $loginState === ''
                                ? ''
                                : '?' . http_build_query(['state' => $loginState], '', '&', PHP_QUERY_RFC3986)
                        ),
                    ],
                    $methods->providers,
                ),
                'signUpHref' => $methods->signUp
                    ? AccountPages::withState(AccountPages::SIGN_UP_PATH, $loginState)
                    : '',
                'forgotHref' => $methods->passwordReset
                    ? AccountPages::withState(AccountPages::FORGOT_PATH, $loginState)
                    : '',
                'passkeyOptions' => $passkey === null
                    ? null
                    : json_encode(PasskeyPages::requestOptions($passkey), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            ],
            error: $error,
            status: $status,
            formOrigins: $formOrigins,
            script: $passkey === null ? null : PasskeyPages::SCRIPT,
        );
    }

    /**
     * What a page for a held request that is gone shows instead of a form (#218): nothing was signed
     * in, and only the application can start again. Shown by the login and sign-up pages, and by every
     * first factor refused with {@see \Clavia\Application\Authentication\SignIn\SignInRequestExpired}.
     */
    public static function expired(): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::login-expired',
            title: Message::of('login.expired.title'),
            heading: Message::of('login.expired.title'),
            returnTo: self::address(null),
            error: Message::of(self::EXPIRED_REQUEST),
            status: StatusCodeInterface::STATUS_BAD_REQUEST,
        );
    }

    /**
     * What a signed-in visitor with nothing to return to sees instead of the form.
     */
    public static function signedIn(string $email): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::login',
            title: Message::of('login.signed_in.title'),
            heading: Message::of('login.signed_in.heading'),
            returnTo: self::address(null),
            variables: [
                'loginState' => '',
                'email' => '',
                'signedInAs' => $email,
                'password' => false,
                'emailSignIn' => false,
                'providers' => [],
                'signUpHref' => '',
                'forgotHref' => '',
                'passkeyOptions' => null,
            ],
        );
    }

    /**
     * The login page's own address — where the theme toggle comes back to. Rebuilt
     * rather than taken from the request, so a page re-rendered by a failed POST still
     * returns to the same authorization request.
     */
    private static function address(?string $loginState): string
    {
        return $loginState === null || $loginState === ''
            ? '/auth/login'
            : '/auth/login?' . http_build_query(['state' => $loginState], '', '&', PHP_QUERY_RFC3986);
    }
}
