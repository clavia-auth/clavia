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
use Clavia\Application\Authentication\Account\AccountMail;
use Clavia\Application\Authentication\Account\SignUpFailure;

/**
 * The self-service account pages: sign-up, "check your inbox", the verification link's
 * confirmation, and the two halves of a password reset.
 *
 * Every page that comes from a login page keeps its handle, so the person returns to the
 * same authorization request; every page a link opens on rebuilds its own address, which
 * carries the token, for the theme toggle to come back to.
 */
final class AccountPages
{
    public const string SIGN_UP_PATH = '/auth/signup';

    public const string FORGOT_PATH = '/auth/password/forgot';

    public const string INVALID_LINK =
        'This link is not valid any more. It may have been used already, or have expired.';

    public const string SIGN_UP_UNAVAILABLE = 'Creating an account is not available for this application.';

    public const string TOO_MANY_SIGN_UPS = 'Too many accounts were created from here. Try again in an hour.';

    public const string ADDRESS_TAKEN = 'This address already has an account. Sign in, or reset your password.';

    public const string RESET_UNAVAILABLE = 'Resetting a password is not available for this application.';

    private function __construct()
    {
    }

    /**
     * @param list<string> $formOrigins
     */
    public static function signUp(
        ?string $loginState,
        array $formOrigins,
        bool $requiresVerification,
        string $email = '',
        ?string $error = null,
        int $status = 200,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::signup',
            title: 'Create an account',
            heading: 'Create an account',
            returnTo: self::withState(self::SIGN_UP_PATH, $loginState),
            variables: [
                'loginState' => $loginState ?? '',
                'email' => $email,
                'requiresVerification' => $requiresVerification,
                'loginHref' => self::withState('/auth/login', $loginState),
            ],
            error: $error,
            status: $status,
            formOrigins: $formOrigins,
        );
    }

    /** The sign-up form refused for a reason the person can act on. */
    public static function signUpMessage(SignUpFailure $reason, string $detail): string
    {
        return match ($reason) {
            SignUpFailure::InvalidEmail => LoginPages::INVALID_EMAIL,
            SignUpFailure::PasswordRejected => $detail,
            SignUpFailure::NotAvailable => self::SIGN_UP_UNAVAILABLE,
            SignUpFailure::TooManySignUps => self::TOO_MANY_SIGN_UPS,
            SignUpFailure::AddressTaken => self::ADDRESS_TAKEN,
        };
    }

    public static function signUpStatus(SignUpFailure $reason): int
    {
        return match ($reason) {
            SignUpFailure::TooManySignUps => 429,
            SignUpFailure::AddressTaken => 409,
            SignUpFailure::InvalidEmail, SignUpFailure::PasswordRejected, SignUpFailure::NotAvailable => 400,
        };
    }

    /**
     * Something was mailed — or, to someone who must not learn whether an address has an
     * account, may have been.
     *
     * @param 'sign-up'|'reset'|'unverified' $why What the mail is for.
     */
    public static function checkInbox(string $email, string $why, ?string $loginState): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::check-inbox',
            title: 'Check your email',
            heading: 'Check your email',
            returnTo: self::withState('/auth/login', $loginState),
            variables: [
                'email' => $email,
                'why' => $why,
                'loginHref' => self::withState('/auth/login', $loginState),
            ],
        );
    }

    /** The question a verification link opens on. */
    public static function confirmEmail(
        string $email,
        #[\SensitiveParameter] string $token,
        ?string $error = null,
        int $status = 200,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::verify-email',
            title: 'Confirm your email address',
            heading: 'Confirm your email address',
            returnTo: self::linkAddress(AccountMail::VERIFY_PATH, $token),
            variables: ['stage' => 'confirm', 'email' => $email, 'token' => $token, 'loginHref' => '/auth/login'],
            error: $error,
            status: $status,
        );
    }

    public static function emailVerified(string $email, ?string $loginState): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::verify-email',
            title: 'Email address confirmed',
            heading: 'Email address confirmed',
            returnTo: self::withState('/auth/login', $loginState),
            variables: [
                'stage' => 'verified',
                'email' => $email,
                'token' => '',
                'loginHref' => self::withState('/auth/login', $loginState),
            ],
        );
    }

    /** A dead link, for either purpose. */
    public static function invalidLink(): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::verify-email',
            title: 'Link not valid',
            heading: 'Link not valid',
            returnTo: '/auth/login',
            variables: ['stage' => 'failed', 'email' => '', 'token' => '', 'loginHref' => '/auth/login'],
            error: self::INVALID_LINK,
            status: 400,
        );
    }

    public static function forgot(
        ?string $loginState,
        string $email = '',
        ?string $error = null,
        int $status = 200,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::password-forgot',
            title: 'Reset your password',
            heading: 'Reset your password',
            returnTo: self::withState(self::FORGOT_PATH, $loginState),
            variables: [
                'loginState' => $loginState ?? '',
                'email' => $email,
                'loginHref' => self::withState('/auth/login', $loginState),
            ],
            error: $error,
            status: $status,
        );
    }

    /** The new-password form a reset link opens on. */
    public static function resetForm(
        string $email,
        #[\SensitiveParameter] string $token,
        ?string $error = null,
        int $status = 200,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::password-reset',
            title: 'Choose a new password',
            heading: 'Choose a new password',
            returnTo: self::linkAddress(AccountMail::RESET_PATH, $token),
            variables: ['stage' => 'form', 'email' => $email, 'token' => $token, 'loginHref' => '/auth/login'],
            error: $error,
            status: $status,
        );
    }

    public static function passwordChanged(string $email, ?string $loginState): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::password-reset',
            title: 'Password changed',
            heading: 'Password changed',
            returnTo: self::withState('/auth/login', $loginState),
            variables: [
                'stage' => 'changed',
                'email' => $email,
                'token' => '',
                'loginHref' => self::withState('/auth/login', $loginState),
            ],
        );
    }

    /** Where a link-opened page lives: its own path with the token, rebuilt, never taken from the request. */
    public static function linkAddress(string $path, #[\SensitiveParameter] string $token): string
    {
        return $path . '?' . http_build_query(['token' => $token], '', '&', PHP_QUERY_RFC3986);
    }

    /** A page's address with the login page's handle, so the request it serves is not lost. */
    public static function withState(string $path, ?string $loginState): string
    {
        return $loginState === null || $loginState === ''
            ? $path
            : $path . '?' . http_build_query(['state' => $loginState], '', '&', PHP_QUERY_RFC3986);
    }
}
