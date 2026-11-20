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
use Clavia\Application\Authentication\Mfa\MfaStatus;
use Clavia\Application\Authentication\Mfa\TotpEnrollment;

/**
 * The view models of the two-factor pages: the second step of a sign-in, and the
 * settings where the account holder turns it on and off.
 */
final class MfaPages
{
    public const string CHALLENGE_PATH = '/auth/mfa';

    public const string SETTINGS_PATH = '/auth/mfa/enroll';

    public const string INVALID_CODE = 'That code is not valid.';

    public const string INVALID_SETUP_CODE = 'That code is not valid. Check your device clock and try again.';

    /**
     * Configuration, not the person's mistake — said plainly rather than as a 500,
     * because whoever reads it on a fresh deployment is the one who can fix it.
     */
    public const string ENCRYPTION_UNAVAILABLE = 'Two-factor authentication cannot be set up on this server yet: '
        . 'CLAVIA_SECRET_ENCRYPTION_KEY is not configured.';

    private function __construct()
    {
    }

    /**
     * The second step: a code from the app, or a recovery code.
     *
     * @param list<string> $formOrigins Where the finished sign-in may go on to.
     */
    public static function challenge(array $formOrigins, ?string $error = null, int $status = 200): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::mfa-challenge',
            title: 'Two-factor authentication',
            heading: 'Check your authenticator',
            returnTo: self::CHALLENGE_PATH,
            error: $error,
            status: $status,
            formOrigins: $formOrigins,
        );
    }

    /** Whether it is on, and the way to change that. */
    public static function settings(MfaStatus $status, ?string $error = null, int $httpStatus = 200): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::mfa-settings',
            title: 'Two-factor authentication',
            heading: 'Two-factor authentication',
            returnTo: self::SETTINGS_PATH,
            variables: [
                'email' => $status->email,
                'enabled' => $status->enabled,
                'recoveryCodesLeft' => $status->recoveryCodesLeft,
            ],
            error: $error,
            status: $httpStatus,
        );
    }

    /** The seed to scan or type, and the field for the code that proves it. */
    public static function setUp(TotpEnrollment $enrollment, ?string $error = null, int $status = 200): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::mfa-setup',
            title: 'Set up two-factor authentication',
            heading: 'Scan this code',
            variables: ['secret' => $enrollment->secret, 'qrSvg' => QrCodeSvg::of($enrollment->provisioningUri)],
            error: $error,
            status: $status,
            wide: true,
        );
    }

    /**
     * The recovery codes, shown this once.
     *
     * @param list<string> $codes
     */
    public static function recoveryCodes(array $codes): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::mfa-codes',
            title: 'Recovery codes',
            heading: 'Two-factor authentication is on',
            variables: ['codes' => $codes],
            wide: true,
        );
    }
}
