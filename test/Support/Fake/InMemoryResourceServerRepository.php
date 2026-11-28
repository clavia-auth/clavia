<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use LogicException;

final class InMemoryResourceServerRepository implements ResourceServerRepository
{
    /** @var array<string, ResourceServer> By id. */
    private array $resourceServers = [];

    /**
     * @param InMemoryClientGrantRepository|null $clientGrants The grants a deleted API takes with it.
     * @param InMemoryIdentityFeedOutbox|null $feed The identity feed's entries a deleted API takes with it.
     */
    public function __construct(
        private readonly ?InMemoryClientGrantRepository $clientGrants = null,
        private readonly ?InMemoryIdentityFeedOutbox $feed = null,
    ) {
    }

    #[\Override]
    public function find(ResourceServerId $id): ?ResourceServer
    {
        return $this->resourceServers[$id->value] ?? null;
    }

    #[\Override]
    public function findByIdentifier(Audience $identifier): ?ResourceServer
    {
        foreach ($this->resourceServers as $resourceServer) {
            if ($resourceServer->identifier->equals($identifier)) {
                return $resourceServer;
            }
        }

        return null;
    }

    #[\Override]
    public function save(ResourceServer $resourceServer): void
    {
        $stored = $this->resourceServers[$resourceServer->id->value] ?? null;
        if ($stored !== null && ! $stored->identifier->equals($resourceServer->identifier)) {
            throw new LogicException("An API's identifier cannot change.");
        }
        $other = $this->findByIdentifier($resourceServer->identifier);
        if ($other !== null && ! $other->id->equals($resourceServer->id)) {
            throw new AlreadyExists('An API is already registered with this identifier.');
        }
        // The key of `authorization_clients`: a client speaks for one API at most.
        foreach ($resourceServer->authorization->clients ?? [] as $client) {
            foreach ($this->resourceServers as $stored) {
                $elsewhere = ! $stored->id->equals($resourceServer->id);
                if ($elsewhere && $stored->authorization?->speaksFor($client) === true) {
                    throw new AlreadyExists('A client already speaks for another API.');
                }
            }
        }

        $this->resourceServers[$resourceServer->id->value] = $resourceServer;
    }

    #[\Override]
    public function delete(ResourceServerId $id): void
    {
        unset($this->resourceServers[$id->value]);
        // The table's ON DELETE CASCADE.
        $this->clientGrants?->forgetApi($id);
        $this->feed?->forgetApi($id);
    }

    #[\Override]
    public function page(PageRequest $request): Page
    {
        return InMemoryPaging::page(
            array_values($this->resourceServers),
            $request,
            static fn (ResourceServer $api): array => [$api->identifier->value, $api->name],
            static fn (ResourceServer $api): array => [$api->createdAt, $api->id->value],
        );
    }

    #[\Override]
    public function withAuthorization(): array
    {
        $apis = array_values(array_filter(
            $this->resourceServers,
            static fn (ResourceServer $api): bool => $api->authorization !== null,
        ));
        usort(
            $apis,
            static fn (ResourceServer $a, ResourceServer $b): int => [$a->createdAt, $a->id->value]
                <=> [$b->createdAt, $b->id->value],
        );

        return $apis;
    }

    #[\Override]
    public function spokenForBy(ClientId $client): ?ResourceServer
    {
        foreach ($this->resourceServers as $api) {
            if ($api->authorization?->speaksFor($client) === true) {
                return $api;
            }
        }

        return null;
    }
}
