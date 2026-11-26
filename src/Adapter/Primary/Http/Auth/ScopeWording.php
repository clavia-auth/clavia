<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Application\OAuth2\Consent\ConsentedApi;
use Clavia\Application\OAuth2\Consent\ScopeLine;

/**
 * The scopes a consent or a device approval asks for, as `partial::scopes` prints them: an OpenID Connect
 * scope this server describes by its message (worded in the page's language), anything else by the words
 * it came with: an API's permission by its operator's description, an unknown scope by its value.
 */
final class ScopeWording
{
    /** The messages of the standard scopes; a scope not listed here is shown as it is. */
    private const array MESSAGES = [
        'openid' => 'consent.scope.openid',
        'profile' => 'consent.scope.profile',
        'email' => 'consent.scope.email',
        'offline_access' => 'consent.scope.offline_access',
    ];

    private function __construct()
    {
    }

    /**
     * @param list<ScopeLine> $oidc
     *
     * @return array{
     *     oidc: list<array{value: string, key: string|null, text: string}>,
     *     api: array{name: string, permissions: list<array{value: string, key: null, text: string}>}|null,
     * }
     */
    public static function of(array $oidc, ?ConsentedApi $api): array
    {
        return [
            'oidc' => array_map(
                static fn (ScopeLine $line): array => [
                    'value' => $line->value,
                    'key' => self::MESSAGES[$line->value] ?? null,
                    'text' => $line->description,
                ],
                $oidc,
            ),
            'api' => $api === null || $api->permissions === [] ? null : [
                'name' => $api->name,
                'permissions' => array_map(
                    static fn (ScopeLine $line): array => [
                        'value' => $line->value,
                        'key' => null,
                        'text' => $line->description,
                    ],
                    $api->permissions,
                ),
            ],
        ];
    }
}
