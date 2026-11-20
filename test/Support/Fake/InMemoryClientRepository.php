<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/**
 * Clients kept in an array, in the order they were first saved.
 */
final class InMemoryClientRepository implements ClientRepository
{
    /** @var array<string, Client> */
    private array $clients = [];

    #[\Override]
    public function find(ClientId $id): ?Client
    {
        return $this->clients[$id->value] ?? null;
    }

    #[\Override]
    public function findByName(string $name): ?Client
    {
        $named = array_filter($this->clients, static fn (Client $client): bool => $client->name === $name);
        usort(
            $named,
            static fn (Client $a, Client $b): int => [$a->createdAt, $a->id->value] <=> [$b->createdAt, $b->id->value],
        );

        return $named[0] ?? null;
    }

    #[\Override]
    public function registersRedirectOrigin(string $origin): bool
    {
        return array_any(
            $this->clients,
            static fn (Client $client): bool => in_array($origin, $client->redirectOrigins(), true),
        );
    }

    #[\Override]
    public function save(Client $client): void
    {
        $this->clients[$client->id->value] = $client;
    }

    #[\Override]
    public function delete(ClientId $id): void
    {
        unset($this->clients[$id->value]);
    }

    #[\Override]
    public function page(PageRequest $request): Page
    {
        return InMemoryPaging::page(
            array_values($this->clients),
            $request,
            static fn (Client $client): array => [$client->id->value, $client->name],
            static fn (Client $client): array => [$client->createdAt, $client->id->value],
        );
    }

    /**
     * @return list<Client> Everything stored, for assertions.
     */
    public function all(): array
    {
        return array_values($this->clients);
    }
}
