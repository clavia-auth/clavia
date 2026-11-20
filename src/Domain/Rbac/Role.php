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
    ) {
    }

    /**
     * Create a role, or rebuild one from storage: the same rules apply to both.
     *
     * @param list<GrantedPermission> $permissions A permission listed twice is granted once.
     *
     * @throws InvalidValue When the name is blank, longer than 64 characters or not one line, or the
     *                      description is longer than 500 characters or not one line.
     */
    public static function define(
        RoleId $id,
        string $name,
        string $description,
        array $permissions,
        DateTimeImmutable $createdAt,
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

        return new self($id, $name, $description, array_values($byKey), $createdAt);
    }

    /**
     * @throws InvalidValue
     */
    public function renamed(string $name): self
    {
        return self::define($this->id, $name, $this->description, $this->permissions, $this->createdAt);
    }

    /**
     * @throws InvalidValue
     */
    public function described(string $description): self
    {
        return self::define($this->id, $this->name, $description, $this->permissions, $this->createdAt);
    }

    /**
     * The same role granting exactly `$permissions`.
     *
     * @param list<GrantedPermission> $permissions
     */
    public function granting(array $permissions): self
    {
        return self::define($this->id, $this->name, $this->description, $permissions, $this->createdAt);
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

    private static function isOneLine(string $text, int $maxLength): bool
    {
        return mb_check_encoding($text, 'UTF-8')
            && mb_strlen($text, 'UTF-8') <= $maxLength
            && preg_match('/[\x00-\x1F\x7F]/', $text) !== 1;
    }
}
