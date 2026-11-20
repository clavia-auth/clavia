<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

/**
 * The profile members of the `UserCreate` and `UserUpdate` bodies — the OIDC
 * `profile` claims an operator may set — in the shape the use cases take them.
 */
final class UserFields
{
    public const array PROFILE = ['name', 'given_name', 'family_name', 'nickname', 'picture', 'locale'];

    private function __construct()
    {
    }

    /**
     * The profile members the body sets, null where it clears one.
     *
     * @return array<'name'|'given_name'|'family_name'|'nickname'|'picture'|'locale', string|null>
     */
    public static function profileChanges(JsonObject $body): array
    {
        $changes = [];
        foreach (self::PROFILE as $field) {
            if ($body->has($field)) {
                $changes[$field] = $body->string($field);
            }
        }

        return $changes;
    }

    /**
     * The profile members the body gives a value.
     *
     * @return array<'name'|'given_name'|'family_name'|'nickname'|'picture'|'locale', string>
     */
    public static function profile(JsonObject $body): array
    {
        return array_filter(self::profileChanges($body), static fn (?string $value): bool => $value !== null);
    }
}
