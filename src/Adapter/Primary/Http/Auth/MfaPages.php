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
use Clavia\Application\Authentication\Mfa\EnrolmentOnTheWay;
use Clavia\Application\Authentication\Mfa\MfaStatus;
use Clavia\Application\Authentication\Mfa\SecondFactorPage;
use Clavia\Application\Authentication\Mfa\TotpEnrollment;
use Clavia\Application\Authentication\Passkey\AssertionOptions;
use Fig\Http\Message\StatusCodeInterface;

/**
 * The view models of the two-factor pages: the second step of a sign-in, and the
 * settings where the account holder turns it on and off.
 */
final class MfaPages
{
    public const string CHALLENGE_PATH = '/auth/mfa';

    public const string SETTINGS_PATH = '/auth/mfa/enroll';

    /** Back to the request that sent the person to set a second factor up. */
    public const string CONTINUE_PATH = '/auth/mfa/enroll/continue';

    public const string INVALID_CODE = 'mfa.error.invalid_code';

    public const string INVALID_PASSKEY = 'mfa.error.invalid_passkey';

    public const string INVALID_SETUP_CODE = 'mfa.error.invalid_setup_code';

    /**
     * Configuration, not the person's mistake — said plainly rather than as a 500,
     * because whoever reads it on a fresh deployment is the one who can fix it.
     */
    public const string ENCRYPTION_UNAVAILABLE = 'mfa.error.encryption_unavailable';

    private function __construct()
    {
    }

    /**
     * The second step: a passkey when the account holds one, a code from the app when it uses
     * one, and a recovery code either way. With a passkey the page loads `passkeys.js`, and
     * carries the ceremony's options in an escaped attribute.
     */
    public static function challenge(
        SecondFactorPage $page,
        ?AssertionOptions $passkey = null,
        ?Message $error = null,
        int $status = StatusCodeInterface::STATUS_OK,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::mfa-challenge',
            title: Message::of('mfa.title'),
            heading: Message::of(
                $passkey !== null || $page->stepUp ? 'mfa.challenge.heading_confirm' : 'mfa.challenge.heading_app',
            ),
            returnTo: self::CHALLENGE_PATH,
            variables: [
                'authenticatorApp' => $page->authenticatorApp,
                'codeField' => $page->authenticatorApp || $page->recoveryCode,
                'recoveryCode' => $page->recoveryCode,
                // A step-up says who asks for more, and why the person signed in is asked again.
                'stepUp' => $page->stepUp,
                'application' => $page->application,
                'passkeyOptions' => $passkey === null
                    ? null
                    : json_encode(PasskeyPages::requestOptions($passkey), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            ],
            error: $error,
            status: $status,
            formOrigins: $page->formOrigins,
            script: $passkey === null ? null : PasskeyPages::SCRIPT,
        );
    }

    /**
     * Whether it is on, the account's passkeys, and the way to change either — or, on the way to
     * an application requiring a second factor, what it asks and the ways to set one up.
     */
    public static function settings(
        MfaStatus $status,
        ?Message $error = null,
        int $httpStatus = StatusCodeInterface::STATUS_OK,
        ?EnrolmentOnTheWay $onTheWay = null,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::mfa-settings',
            title: Message::of('mfa.title'),
            heading: Message::of($onTheWay === null ? 'mfa.title' : 'mfa.set_up.title'),
            returnTo: self::SETTINGS_PATH,
            variables: [
                'email' => $status->email,
                'enabled' => $status->enabled,
                'recoveryCodesLeft' => $status->recoveryCodesLeft,
                'passkeys' => $status->passkeys,
                'onTheWay' => $onTheWay !== null,
                'application' => $onTheWay?->application,
                'loginState' => $onTheWay->loginState ?? '',
            ],
            error: $error,
            status: $httpStatus,
        );
    }

    /** The seed to scan or type, and the field for the code that proves it. */
    public static function setUp(
        TotpEnrollment $enrollment,
        ?Message $error = null,
        int $status = StatusCodeInterface::STATUS_OK,
        ?EnrolmentOnTheWay $onTheWay = null,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::mfa-setup',
            title: Message::of('mfa.set_up.title'),
            heading: Message::of('mfa.set_up.heading'),
            variables: [
                'secret' => $enrollment->secret,
                'qrSvg' => QrCodeSvg::of($enrollment->provisioningUri),
                'loginState' => $onTheWay->loginState ?? '',
            ],
            error: $error,
            status: $status,
            wide: true,
        );
    }

    /**
     * The recovery codes, shown this once — and, on the way to an application, the way back to it.
     *
     * @param list<string> $codes
     */
    public static function recoveryCodes(array $codes, ?EnrolmentOnTheWay $onTheWay = null): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::mfa-codes',
            title: Message::of('mfa.codes.title'),
            heading: Message::of('mfa.codes.heading'),
            variables: ['codes' => $codes, 'loginState' => $onTheWay->loginState ?? ''],
            wide: true,
            // Continuing ends at the application's redirect URI (see the auth pages' CSP).
            formOrigins: $onTheWay === null ? [] : $onTheWay->formOrigins,
        );
    }
}
