<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Provisioning\ProvisioningToken;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Provisioning\ProvisioningTokenRepository;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/**
 * Provisioning tokens in memory. The tokens are immutable, so storing them is copying them.
 */
final class InMemoryProvisioningTokenRepository implements ProvisioningTokenRepository
{
    /** @var array<string, ProvisioningToken> By id. */
    private array $tokens = [];

    #[\Override]
    public function add(ProvisioningToken $token): void
    {
        $this->tokens[$token->id->value] = $token;
    }

    #[\Override]
    public function find(ProvisioningTokenId $id): ?ProvisioningToken
    {
        return $this->tokens[$id->value] ?? null;
    }

    #[\Override]
    public function findByDigest(Digest $digest): ?ProvisioningToken
    {
        foreach ($this->tokens as $token) {
            if ($token->digest->equals($digest)) {
                return $token;
            }
        }

        return null;
    }

    #[\Override]
    public function save(ProvisioningToken $token): void
    {
        $stored = $this->tokens[$token->id->value] ?? null;
        if ($stored !== null && $token->revokedAt !== null) {
            // As in storage: only the revocation is written.
            $this->tokens[$token->id->value] = $stored->revoke($token->revokedAt);
        }
    }

    #[\Override]
    public function page(PageRequest $request, ?ConnectionName $connection = null): Page
    {
        return InMemoryPaging::page(
            array_values(array_filter(
                $this->tokens,
                static fn (ProvisioningToken $token): bool => $connection === null
                    || $token->connection->equals($connection),
            )),
            $request,
            static fn (ProvisioningToken $token): array => [$token->description],
            static fn (ProvisioningToken $token): array => [$token->createdAt, $token->id->value],
        );
    }

    /** As the foreign key does: a connection's tokens go with it. */
    public function deleteConnection(ConnectionName $connection): void
    {
        $this->tokens = array_filter(
            $this->tokens,
            static fn (ProvisioningToken $token): bool => ! $token->connection->equals($connection),
        );
    }
}
