<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Roles;

use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Scope;

/**
 * The bridge between what a role grants and what the APIs define: references checked
 * against the APIs on the way in, permissions described from them on the way out.
 *
 * A role must only ever point at a permission an API actually defines — storage holds
 * the link as a foreign key, and this is where a wrong reference is told apart from a
 * fault, as the caller's mistake.
 */
final readonly class RolePermissions
{
    public function __construct(private ResourceServerRepository $resourceServers)
    {
    }

    /**
     * @param list<PermissionReference> $references A permission named twice is granted once.
     *
     * @return list<GrantedPermission>
     *
     * @throws InvalidValue When a reference names an API that does not exist or a permission it
     *                      does not define.
     */
    public function resolve(array $references): array
    {
        $granted = [];
        foreach ($references as $reference) {
            $api = $this->api($reference->resourceServerId);
            if ($api === null || ! $api->defines($reference->value)) {
                throw new InvalidValue(sprintf(
                    "No permission '%s' is defined by the API '%s'.",
                    $reference->value,
                    $reference->resourceServerId,
                ));
            }
            $granted[] = new GrantedPermission($api->id, Scope::fromString($reference->value));
        }

        return $granted;
    }

    /**
     * @param list<GrantedPermission> $permissions
     *
     * @return list<DescribedPermission> By API identifier, then value.
     */
    public function describe(array $permissions): array
    {
        /** @var array<string, ResourceServer|null> $apis */
        $apis = [];
        $described = [];
        foreach ($permissions as $granted) {
            $key = $granted->resourceServerId->value;
            if (! array_key_exists($key, $apis)) {
                $apis[$key] = $this->resourceServers->find($granted->resourceServerId);
            }
            $api = $apis[$key];
            $permission = $api === null ? null : self::definition($api, $granted->value);
            if ($api === null || $permission === null) {
                // Withdrawn since it was read: storage's cascade has the last word.
                continue;
            }
            $described[] = new DescribedPermission($api->id, $api->identifier, $granted->value->value, $permission);
        }
        usort($described, self::compare(...));

        return $described;
    }

    /** By API identifier, then value: how a person scans a list of permissions. */
    public static function compare(DescribedPermission $a, DescribedPermission $b): int
    {
        return [$a->resourceServerIdentifier->value, $a->value] <=> [$b->resourceServerIdentifier->value, $b->value];
    }

    private function api(string $id): ?ResourceServer
    {
        try {
            return $this->resourceServers->find(ResourceServerId::fromString($id));
        } catch (InvalidValue) {
            return null;
        }
    }

    /** The description of `$value` on `$api`, or null when the API does not define it. */
    private static function definition(ResourceServer $api, Scope $value): ?string
    {
        foreach ($api->permissions as $permission) {
            if ($permission->value->equals($value)) {
                return $permission->description;
            }
        }

        return null;
    }
}
