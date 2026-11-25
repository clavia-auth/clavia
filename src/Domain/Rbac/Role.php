<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Rbac;

use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Scope;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;

/**
 * A named set of permissions, possibly across several APIs, that users are given.
 *
 * Roles are how a *person* comes to hold a permission. On an API that enforces them
 * ({@see \Clavia\Domain\ResourceServer\ResourceServer::$enforcePolicies}), a token issued
 * on someone's behalf carries only what their roles grant there, re-read at every
 * issuance. A machine client acting as itself has no roles: its client grant governs it.
 *
 * A **provisionable** role is one a directory's SCIM group may grant (docs/design/scim-provisioning.md
 * §2): the group whose `displayName` is its name gives it to its members. Such a role never holds a
 * permission on a system API, whichever way round it is attempted, so a directory's token can never
 * make anyone an administrator of this server.
 */
final readonly class Role
{
    public const int MAX_NAME_LENGTH = 64;

    public const int MAX_DESCRIPTION_LENGTH = 500;

    /**
     * @param list<GrantedPermission> $permissions Unique, sorted by API then value.
     */
    private function __construct(
        public RoleId $id,
        public string $name,
        public string $description,
        public array $permissions,
        public DateTimeImmutable $createdAt,
        public bool $provisionable = false,
    ) {
    }

    /**
     * Create a role, or rebuild one from storage: the same rules apply to both.
     *
     * @param list<GrantedPermission> $permissions A permission listed twice is granted once.
     *
     * @throws InvalidValue When the name is blank, longer than 64 characters or not one line, the
     *                      description is longer than 500 characters or not one line, or a
     *                      provisionable role would hold a permission on a system API.
     */
    public static function define(
        RoleId $id,
        string $name,
        string $description,
        array $permissions,
        DateTimeImmutable $createdAt,
        bool $provisionable = false,
    ): self {
        if (! self::isOneLine($name, self::MAX_NAME_LENGTH) || trim($name) === '') {
            throw new InvalidValue('A role name is 1 to 64 characters on one line.');
        }
        if (! self::isOneLine($description, self::MAX_DESCRIPTION_LENGTH)) {
            throw new InvalidValue('A role description is at most 500 characters on one line.');
        }

        $byKey = [];
        foreach ($permissions as $permission) {
            $byKey[$permission->key()] = $permission;
        }
        ksort($byKey, SORT_STRING);
        $onSystemApi = array_filter($byKey, static fn (GrantedPermission $granted): bool => $granted->onSystemApi);
        if ($provisionable && $onSystemApi !== []) {
            throw new InvalidValue(
                'A role a directory may grant holds no permission on a system API, such as the Management API.',
            );
        }

        return new self($id, $name, $description, array_values($byKey), $createdAt, $provisionable);
    }

    /**
     * The same role, which a directory's group may grant or not.
     *
     * @throws InvalidValue When it holds a permission on a system API.
     */
    public function withProvisionable(bool $provisionable): self
    {
        return $this->rebuilt(provisionable: $provisionable);
    }

    /**
     * @throws InvalidValue
     */
    public function renamed(string $name): self
    {
        return $this->rebuilt(name: $name);
    }

    /**
     * @throws InvalidValue
     */
    public function described(string $description): self
    {
        return $this->rebuilt(description: $description);
    }

    /**
     * The same role granting exactly `$permissions`.
     *
     * @param list<GrantedPermission> $permissions
     *
     * @throws InvalidValue When a provisionable role would hold a permission on a system API.
     */
    public function granting(array $permissions): self
    {
        return $this->rebuilt(permissions: $permissions);
    }

    /**
     * The same role granting `$permissions` as well as what it already grants.
     *
     * @param list<GrantedPermission> $permissions
     */
    public function alsoGranting(array $permissions): self
    {
        return $this->granting([...$this->permissions, ...$permissions]);
    }

    /** What this role grants on one API. */
    public function grantsOn(ResourceServerId $resourceServerId): ScopeSet
    {
        return ScopeSet::of(...array_map(
            static fn (GrantedPermission $permission): Scope => $permission->value,
            array_values(array_filter(
                $this->permissions,
                static fn (GrantedPermission $granted): bool => $granted->resourceServerId->equals($resourceServerId),
            )),
        ));
    }

    /**
     * The role with one thing changed, held to every rule again.
     *
     * @param list<GrantedPermission>|null $permissions
     *
     * @throws InvalidValue
     */
    private function rebuilt(
        ?string $name = null,
        ?string $description = null,
        ?array $permissions = null,
        ?bool $provisionable = null,
    ): self {
        return self::define(
            $this->id,
            $name ?? $this->name,
            $description ?? $this->description,
            $permissions ?? $this->permissions,
            $this->createdAt,
            $provisionable ?? $this->provisionable,
        );
    }

    private static function isOneLine(string $text, int $maxLength): bool
    {
        return mb_check_encoding($text, 'UTF-8')
            && mb_strlen($text, 'UTF-8') <= $maxLength
            && preg_match('/[\x00-\x1F\x7F]/', $text) !== 1;
    }
}
