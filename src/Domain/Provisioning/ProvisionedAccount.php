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
 * The link between SCIM's keys and an account (docs/design/scim-provisioning.md §4): the `userName`
 * and `externalId` a directory knows the person by, beside the `User` that is the account.
 *
 * Clavia's accounts are keyed by address, SCIM's by `userName`; keeping both lets a directory rename
 * one without the other. `userName` is unique per connection ignoring case (RFC 7643 §4.1.1), by its
 * key; `externalId` is unique per connection exactly. A directory sees and lists only the accounts it
 * provisioned.
 */
final readonly class ProvisionedAccount
{
    /**
     * @param non-empty-string      $userName
     * @param non-empty-string|null $externalId
     */
    private function __construct(
        public UserId $userId,
        public ConnectionName $connection,
        public string $userName,
        public ?string $externalId,
        public ProvisioningTokenId $provisionedBy,
        public DateTimeImmutable $createdAt,
        public DateTimeImmutable $updatedAt,
    ) {
    }

    /** The account a directory just provisioned. */
    public static function provision(
        UserId $userId,
        ConnectionName $connection,
        ScimUser $resource,
        ProvisioningTokenId $provisionedBy,
        DateTimeImmutable $now,
    ): self {
        return new self($userId, $connection, $resource->userName, $resource->externalId, $provisionedBy, $now, $now);
    }

    /**
     * @param non-empty-string      $userName
     * @param non-empty-string|null $externalId
     */
    public static function reconstitute(
        UserId $userId,
        ConnectionName $connection,
        string $userName,
        ?string $externalId,
        ProvisioningTokenId $provisionedBy,
        DateTimeImmutable $createdAt,
        DateTimeImmutable $updatedAt,
    ): self {
        return new self($userId, $connection, $userName, $externalId, $provisionedBy, $createdAt, $updatedAt);
    }

    /** What `userName` is unique and compared by: ignoring case. */
    public static function keyOf(string $userName): string
    {
        return mb_strtolower($userName, 'UTF-8');
    }

    public function userNameKey(): string
    {
        return self::keyOf($this->userName);
    }
}
