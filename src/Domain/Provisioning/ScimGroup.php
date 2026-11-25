<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Provisioning;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use DateTimeImmutable;

/**
 * A directory's group (docs/design/scim-provisioning.md §5.5): a name and members, accounts of the
 * same connection. A group grants nothing of itself; one whose `displayName` is a provisionable
 * role's name gives that role to its members, and takes it back when they leave or it goes.
 *
 * Its name is unique in its connection ignoring case, so a group names one role; `externalId` is
 * unique exactly.
 */
final readonly class ScimGroup
{
    /**
     * @param non-empty-string      $displayName
     * @param non-empty-string|null $externalId
     * @param list<UserId>          $members
     */
    private function __construct(
        public ScimGroupId $id,
        public ConnectionName $connection,
        public string $displayName,
        public ?string $externalId,
        public array $members,
        public ProvisioningTokenId $provisionedBy,
        public DateTimeImmutable $createdAt,
        public DateTimeImmutable $updatedAt,
    ) {
    }

    /** @param list<UserId> $members The accounts the resource names, each checked to be the connection's. */
    public static function provision(
        ScimGroupId $id,
        ConnectionName $connection,
        ScimGroupResource $resource,
        array $members,
        ProvisioningTokenId $provisionedBy,
        DateTimeImmutable $now,
    ): self {
        return new self(
            $id,
            $connection,
            $resource->displayName,
            $resource->externalId,
            $members,
            $provisionedBy,
            $now,
            $now,
        );
    }

    /**
     * @param non-empty-string      $displayName
     * @param non-empty-string|null $externalId
     * @param list<UserId>          $members
     */
    public static function reconstitute(
        ScimGroupId $id,
        ConnectionName $connection,
        string $displayName,
        ?string $externalId,
        array $members,
        ProvisioningTokenId $provisionedBy,
        DateTimeImmutable $createdAt,
        DateTimeImmutable $updatedAt,
    ): self {
        return new self($id, $connection, $displayName, $externalId, $members, $provisionedBy, $createdAt, $updatedAt);
    }

    /**
     * The group as the resource now says, with these members.
     *
     * @param list<UserId> $members
     */
    public function changedTo(ScimGroupResource $resource, array $members, DateTimeImmutable $now): self
    {
        return new self(
            $this->id,
            $this->connection,
            $resource->displayName,
            $resource->externalId,
            $members,
            $this->provisionedBy,
            $this->createdAt,
            $now,
        );
    }

    /** What the name is unique and compared by: ignoring case. */
    public static function keyOf(string $displayName): string
    {
        return mb_strtolower($displayName, 'UTF-8');
    }

    public function displayNameKey(): string
    {
        return self::keyOf($this->displayName);
    }

    /** The resource as it stands: what a `PATCH` is applied to. */
    public function resource(): ScimGroupResource
    {
        return ScimGroupResource::fromJson((object) array_filter([
            'displayName' => $this->displayName,
            'externalId' => $this->externalId,
            'members' => array_map(static fn (UserId $id): object => (object) ['value' => $id->value], $this->members),
        ], static fn (mixed $value): bool => $value !== null));
    }

    /**
     * Its version (RFC 7644 §3.14): its last change, to the microsecond.
     *
     * @return non-empty-string
     */
    public function version(): string
    {
        return $this->updatedAt->format('Uu');
    }

    /** @param list<string>|null $expected The versions `If-Match` names; null when there is none. */
    public function isAt(?array $expected): bool
    {
        return $expected === null || in_array('*', $expected, true) || in_array($this->version(), $expected, true);
    }
}
