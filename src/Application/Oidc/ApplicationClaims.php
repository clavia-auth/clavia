<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc;

use Clavia\Domain\Claims\ClaimDestination;
use Clavia\Domain\Claims\ClaimSourceKind;
use Clavia\Domain\Claims\ClaimSubject;
use Clavia\Domain\Claims\CustomClaims;
use Clavia\Domain\Claims\CustomClaimsTooLarge;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleRepository;

/**
 * The custom claims an application's mappings give its ID tokens or its userinfo answers about a
 * person (docs/design/custom-claims.md §5.3, §5.4), from the account as it is now. Nothing for a
 * third-party application, which cannot hold mappings anyway. The roles are all of the person's:
 * an application, unlike an API, is not one place of permissions among others.
 */
final readonly class ApplicationClaims
{
    public function __construct(
        private ClientRepository $clients,
        private RoleRepository $roles,
    ) {
    }

    /**
     * @return array<non-empty-string, mixed>
     *
     * @throws CustomClaimsTooLarge
     */
    public function for(ClientId $client, User $user, ClaimDestination $destination): array
    {
        $application = $this->clients->find($client);
        if ($application === null || $application->claims->isEmpty() || ! $application->isFirstParty()) {
            return [];
        }

        $roles = [];
        foreach ($application->claims->mappings as $mapping) {
            if ($mapping->goesTo($destination) && $mapping->source->kind === ClaimSourceKind::Roles) {
                $roles = array_map(static fn (Role $role): string => $role->name, $this->roles->rolesOf($user->id));
                sort($roles, SORT_STRING);
                break;
            }
        }

        return CustomClaims::of($application->claims, new ClaimSubject($user, $roles), $destination);
    }
}
