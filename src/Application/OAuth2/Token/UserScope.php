<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Token;

use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\ScopeSet;

/**
 * What a token issued on a person's behalf may carry, decided afresh at every issuance —
 * a code redeemed, a refresh — rather than trusted from when it was authorized.
 *
 * Two vocabularies travel in one scope. The OIDC scopes describe the person, who
 * consented to them, and pass untouched. An API's permissions decide what the token can
 * do: only those the API still defines, and on an API that enforces roles only those the
 * person's roles grant there now.
 */
final readonly class UserScope
{
    /**
     * @param ScopeSet $supportedScopes The OIDC scopes, valid whatever API a grant names.
     */
    public function __construct(
        private ResourceServerRepository $resourceServers,
        private RoleRepository $roles,
        private ScopeSet $supportedScopes,
    ) {
    }

    /**
     * `$authorized`, cut to what may be issued now — or why nothing may.
     *
     * @return ScopeSet|OAuth2Error An `invalid_grant` when the API is gone, or when it enforces
     *                              roles and the person holds nothing there any more.
     */
    public function now(ScopeSet $authorized, UserId $user, ?Audience $audience): ScopeSet|OAuth2Error
    {
        if ($audience === null) {
            return $authorized->intersect($this->supportedScopes);
        }

        $resourceServer = $this->resourceServers->findByIdentifier($audience);
        if ($resourceServer === null) {
            return OAuth2Error::invalidGrant('The API this grant was issued for is no longer registered.');
        }

        $apiScopes = $resourceServer->permissionScopes();
        if ($resourceServer->enforcePolicies) {
            $held = $this->roles->permissionsHeld($user, $resourceServer->id);
            if ($held->isEmpty()) {
                // The authorization endpoint refused this person already; roles taken away
                // since then make the grant worthless rather than a token for nothing.
                return OAuth2Error::invalidGrant(
                    'The account no longer holds any permission on the API this grant was issued for.',
                );
            }
            $apiScopes = $apiScopes->intersect($held);
        }

        return $authorized->intersect($this->supportedScopes->union($apiScopes));
    }
}
