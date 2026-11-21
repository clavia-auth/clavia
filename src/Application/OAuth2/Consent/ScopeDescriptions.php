<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Consent;

use Clavia\Domain\Oidc\OidcScope;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\ScopeSet;

/**
 * What a requested scope means, in the words a person is shown: the OIDC scopes as the
 * server describes them, an API's permissions as the API does. The consent screen and the
 * device page put the same question.
 */
final class ScopeDescriptions
{
    private const array OIDC_SCOPES = [
        OidcScope::OPENID => 'Sign you in and know who you are',
        OidcScope::PROFILE => 'See your profile: your name, picture and locale',
        OidcScope::EMAIL => 'See your email address',
    ];

    private function __construct()
    {
    }

    /**
     * @return list<ScopeLine> The OIDC scopes among `$requested`.
     */
    public static function oidc(ScopeSet $requested, ScopeSet $supportedScopes): array
    {
        $lines = [];
        foreach ($requested->intersect($supportedScopes) as $scope) {
            $lines[] = new ScopeLine($scope->value, self::OIDC_SCOPES[$scope->value] ?? $scope->value);
        }

        return $lines;
    }

    /** The API's permissions among `$requested`, under its name. */
    public static function api(ResourceServer $api, ScopeSet $requested): ConsentedApi
    {
        $permissions = [];
        foreach ($api->permissions as $permission) {
            if ($requested->contains($permission->value)) {
                $permissions[] = self::line($permission);
            }
        }

        return new ConsentedApi(
            $api->name === '' ? $api->identifier->value : $api->name,
            $api->identifier->value,
            $permissions,
        );
    }

    private static function line(Permission $permission): ScopeLine
    {
        $value = $permission->value->value;

        return new ScopeLine($value, $permission->description === '' ? $value : $permission->description);
    }
}
