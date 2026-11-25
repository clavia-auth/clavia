<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Token;

use Clavia\Domain\Claims\ClaimDestination;
use Clavia\Domain\Claims\ClaimSourceKind;
use Clavia\Domain\Claims\ClaimSubject;
use Clavia\Domain\Claims\CustomClaims;
use Clavia\Domain\Claims\CustomClaimsTooLarge;
use Clavia\Domain\Client\Ownership;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Identity\UserRepository;

/**
 * The custom claims an API's mappings give one of its access tokens (docs/design/custom-claims.md
 * §5.3, §5.4), worked out from the account as it is now: at issuance (a refresh included, so a
 * changed plan or a role taken away shows on the next token) and at introspection.
 *
 * Nothing for a third-party application: it reads the JWTs it is given, and no consent screen
 * names these claims. Constants only for a token with no person. The roles are those holding a
 * permission on this API: an API learns nothing of the others'.
 */
final readonly class ApiClaims
{
    public function __construct(
        private UserRepository $users,
        private RoleRepository $roles,
    ) {
    }

    /**
     * @return array<non-empty-string, mixed>
     *
     * @throws CustomClaimsTooLarge
     */
    public function for(ResourceServer $api, AccessToken $token): array
    {
        if ($api->claims->isEmpty() || $token->clientId->ownership() === Ownership::ThirdParty) {
            return [];
        }

        $subject = null;
        if ($token->userId !== null) {
            $user = $this->users->find($token->userId);
            if ($user === null) {
                return [];
            }
            $subject = new ClaimSubject($user, $this->readsRoles($api) ? $this->rolesOn($api, $user->id) : []);
        }

        return CustomClaims::of($api->claims, $subject, ClaimDestination::AccessToken);
    }

    private function readsRoles(ResourceServer $api): bool
    {
        foreach ($api->claims->mappings as $mapping) {
            if ($mapping->source->kind === ClaimSourceKind::Roles) {
                return true;
            }
        }

        return false;
    }

    /** @return list<string> */
    private function rolesOn(ResourceServer $api, UserId $user): array
    {
        $names = array_map(
            static fn (Role $role): string => $role->name,
            array_values(array_filter(
                $this->roles->rolesOf($user),
                static fn (Role $role): bool => ! $role->grantsOn($api->id)->isEmpty(),
            )),
        );
        sort($names, SORT_STRING);

        return $names;
    }
}
