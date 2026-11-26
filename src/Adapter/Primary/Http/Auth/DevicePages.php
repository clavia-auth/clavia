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
use Clavia\Application\OAuth2\Device\DeviceReview;
use Fig\Http\Message\StatusCodeInterface;

/**
 * The device page's three stages: the code typed, the question put, the answer recorded.
 */
final class DevicePages
{
    public const string PATH = '/auth/device';

    public const string INVALID_CODE = 'device.error.invalid_code';

    public const string TOO_MANY_CODES = 'device.error.too_many_codes';

    public const string STRONGER_SIGN_IN = 'device.error.stronger_sign_in';

    public const string NO_PERMISSION = 'device.error.no_permission';

    private function __construct()
    {
    }

    public static function entry(
        string $userCode = '',
        ?Message $error = null,
        int $status = StatusCodeInterface::STATUS_OK,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::device',
            title: Message::of('device.entry.title'),
            heading: Message::of('device.entry.title'),
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
            title: Message::of('device.review.title'),
            heading: Message::of('device.review.heading'),
            returnTo: self::address($review->userCode),
            variables: [
                'stage' => 'review',
                'userCode' => $review->userCode,
                'clientName' => $review->clientName,
                'email' => $review->email,
                'scopes' => ScopeWording::of($review->oidcScopes, $review->api),
            ],
        );
    }

    public static function done(bool $approved, bool $noPermission = false): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::device',
            title: Message::of($approved ? 'device.done.connected' : 'device.done.refused'),
            heading: Message::of($approved ? 'device.done.connected' : 'device.done.refused'),
            returnTo: self::PATH,
            variables: ['stage' => 'done', 'approved' => $approved],
            error: $noPermission ? Message::of(self::NO_PERMISSION) : null,
        );
    }

    public static function address(string $userCode): string
    {
        return self::PATH . '?' . http_build_query(['user_code' => $userCode], '', '&', PHP_QUERY_RFC3986);
    }
}
