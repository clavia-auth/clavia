<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Provisioning;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Scope;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Make sure a role exists and grants some permissions on one API: `clavia roles:create`,
 * and the Administrator role `seed-dev` gives the development user.
 *
 * The bootstrap of a deployment's authority, so a shell operation: until somebody holds
 * `update:roles`, nobody can manage roles over HTTP, and this is how the first person
 * comes to. Adds to an existing role rather than replacing what it grants, so running it
 * again never strips something an operator granted since.
 */
final readonly class EnsureRole
{
    public function __construct(
        private RoleRepository $roles,
        private ResourceServerRepository $resourceServers,
        private TransactionManager $transactions,
        private SecretGenerator $secrets,
        private Clock $clock,
    ) {
    }

    /**
     * @param string        $description Used when the role is created; an existing role keeps its own.
     * @param ScopeSet|null $permissions Null for every permission the API defines.
     *
     * @throws NotFound     When no API is registered with the identifier.
     * @throws InvalidValue When the API does not define one of the permissions, or the name is invalid.
     */
    public function __invoke(string $name, string $description, Audience $api, ?ScopeSet $permissions = null): Role
    {
        $resourceServer = $this->resourceServers->findByIdentifier($api) ?? throw NotFound::of('API');
        $wanted = $permissions ?? $resourceServer->permissionScopes();

        $undefined = $wanted->without($resourceServer->permissionScopes());
        if (! $undefined->isEmpty()) {
            throw new InvalidValue(sprintf(
                "The API '%s' does not define: %s.",
                $resourceServer->identifier->value,
                $undefined->toString(),
            ));
        }

        $granted = array_map(
            static fn (Scope $value): GrantedPermission => new GrantedPermission($resourceServer->id, $value),
            iterator_to_array($wanted, false),
        );

        /** @var Role */
        return $this->transactions->transactional(function () use ($name, $description, $granted): Role {
            $existing = $this->roles->findByName($name);
            $role = $existing === null
                ? Role::define(RoleId::generate($this->secrets), $name, $description, $granted, $this->clock->now())
                : $existing->alsoGranting($granted);
            $this->roles->save($role);

            return $role;
        });
    }
}
