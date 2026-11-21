<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Consent;

use Clavia\Application\Authentication\EndUser;
use Clavia\Domain\Oidc\OidcScope;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\Shared\ScopeSet;

/**
 * `GET /auth/consent`: what the screen shows for a request on hold.
 *
 * Only what means something is shown: an OpenID Connect scope this server supports, or a
 * permission the named API defines. Anything else was refused at the authorization
 * endpoint and never reaches here.
 */
final readonly class DescribeConsent
{
    /** What the OIDC scopes mean, in the screen's words. API permissions carry their own. */
    private const array OIDC_SCOPES = [
        OidcScope::OPENID => 'Sign you in and know who you are',
        OidcScope::PROFILE => 'See your profile: your name, picture and locale',
        OidcScope::EMAIL => 'See your email address',
    ];

    /**
     * @param ScopeSet $supportedScopes The OIDC scopes this server issues.
     */
    public function __construct(
        private HeldConsents $held,
        private ScopeSet $supportedScopes,
    ) {
    }

    /**
     * @return ConsentScreen|null Null when the handle stands for nothing the signed-in person may decide.
     */
    public function __invoke(#[\SensitiveParameter] string $handle, EndUser $endUser): ?ConsentScreen
    {
        $held = $this->held->find($handle, $endUser);
        if ($held === null) {
            return null;
        }

        $oidc = [];
        foreach ($held->pending->scope->intersect($this->supportedScopes) as $scope) {
            $oidc[] = new ScopeLine($scope->value, self::OIDC_SCOPES[$scope->value] ?? $scope->value);
        }

        $api = null;
        if ($held->api !== null) {
            $permissions = [];
            foreach ($held->api->permissions as $permission) {
                if ($held->pending->scope->contains($permission->value)) {
                    $permissions[] = self::line($permission);
                }
            }
            $api = new ConsentedApi(
                $held->api->name === '' ? $held->api->identifier->value : $held->api->name,
                $held->api->identifier->value,
                $permissions,
            );
        }

        return new ConsentScreen(
            $held->client->name === '' ? $held->client->id->value : $held->client->name,
            $held->user->email,
            $oidc,
            $api,
            $held->client->redirectOrigins(),
        );
    }

    private static function line(Permission $permission): ScopeLine
    {
        $value = $permission->value->value;

        return new ScopeLine($value, $permission->description === '' ? $value : $permission->description);
    }
}
