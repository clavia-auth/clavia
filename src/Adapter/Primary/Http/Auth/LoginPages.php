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
use Clavia\Application\Authentication\External\ExternalProviderOption;
use Clavia\Application\Authentication\LoginPage\SignInMethods;

/**
 * The view models of the login page, shared by the handler that shows it and the one
 * that re-shows it after a failed attempt — so the two cannot drift.
 */
final class LoginPages
{
    public const string INVALID_CREDENTIALS = 'Incorrect email or password.';

    public const string EXPIRED_FORM = 'Your session expired. Please try again.';

    public const string PASSWORD_UNAVAILABLE = 'Password sign-in is not available for this application.';

    private function __construct()
    {
    }

    /**
     * The sign-in form.
     *
     * @param list<string> $formOrigins
     * @param SignInMethods $methods    The password form when it is offered, the external connections
     *                                  as links below it.
     */
    public static function form(
        ?string $loginState,
        array $formOrigins,
        SignInMethods $methods,
        ?string $email = null,
        ?string $error = null,
        int $status = 200,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::login',
            title: 'Sign in',
            heading: 'Sign in',
            returnTo: self::address($loginState),
            variables: [
                'loginState' => $loginState ?? '',
                'email' => $email ?? '',
                'signedInAs' => null,
                'password' => $methods->password,
                'providers' => array_map(
                    static fn (ExternalProviderOption $provider): array => [
                        'label' => $provider->label,
                        'href' => '/auth/social/' . rawurlencode($provider->name) . (
                            $loginState === null || $loginState === ''
                                ? ''
                                : '?' . http_build_query(['state' => $loginState], '', '&', PHP_QUERY_RFC3986)
                        ),
                    ],
                    $methods->providers,
                ),
            ],
            error: $error,
            status: $status,
            formOrigins: $formOrigins,
        );
    }

    /**
     * What a signed-in visitor with nothing to return to sees instead of the form.
     */
    public static function signedIn(string $email): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::login',
            title: 'Signed in',
            heading: 'You are signed in',
            returnTo: self::address(null),
            variables: [
                'loginState' => '',
                'email' => '',
                'signedInAs' => $email,
                'password' => false,
                'providers' => [],
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
