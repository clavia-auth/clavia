<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Consent;

use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\ScopeSet;

/**
 * The scopes a request asks for, as the consent screen and the device page put the question: the
 * OpenID Connect scopes by their value alone, which the page words in the person's language
 * (docs/design/translated-sign-in-pages.md), and an API's permissions as the API describes them, in the
 * words its operator wrote.
 */
final class ScopeDescriptions
{
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
            // The value stands for its description: wording it is the page's.
            $lines[] = new ScopeLine($scope->value, $scope->value);
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
