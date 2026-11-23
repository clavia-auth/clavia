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
use Clavia\Application\OAuth2\Device\DeviceReview;

/**
 * The device page's three stages: the code typed, the question put, the answer recorded.
 */
final class DevicePages
{
    public const string PATH = '/auth/device';

    public const string INVALID_CODE = 'That code is not valid or has expired. Check the device and try again.';

    public const string TOO_MANY_CODES = 'Too many codes were not valid. Wait a few minutes before trying again.';

    public const string STRONGER_SIGN_IN = 'This application requires two-factor authentication, which this account '
        . 'cannot give yet. Set it up from your account, then try the code again.';

    public const string NO_PERMISSION = 'You do not have permission to use this API, so the device was refused.';

    private function __construct()
    {
    }

    public static function entry(string $userCode = '', ?string $error = null, int $status = 200): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::device',
            title: 'Connect a device',
            heading: 'Connect a device',
            returnTo: self::PATH,
            variables: ['stage' => 'entry', 'userCode' => $userCode],
            error: $error,
            status: $status,
        );
    }

    public static function review(DeviceReview $review): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::device',
            title: 'Allow this device',
            heading: 'Allow this device?',
            returnTo: self::address($review->userCode),
            variables: [
                'stage' => 'review',
                'userCode' => $review->userCode,
                'clientName' => $review->clientName,
                'email' => $review->email,
                'oidcScopes' => $review->oidcScopes,
                'api' => $review->api,
            ],
        );
    }

    public static function done(bool $approved, bool $noPermission = false): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::device',
            title: $approved ? 'Device connected' : 'Device refused',
            heading: $approved ? 'Device connected' : 'Device refused',
            returnTo: self::PATH,
            variables: ['stage' => 'done', 'approved' => $approved],
            error: $noPermission ? self::NO_PERMISSION : null,
        );
    }

    public static function address(string $userCode): string
    {
        return self::PATH . '?' . http_build_query(['user_code' => $userCode], '', '&', PHP_QUERY_RFC3986);
    }
}
