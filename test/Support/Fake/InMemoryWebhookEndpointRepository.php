<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Webhook\WebhookEndpoint;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;

/** Webhook endpoints in memory, in the order they were added, as storage orders them. */
final class InMemoryWebhookEndpointRepository implements WebhookEndpointRepository
{
    /** @var array<string, WebhookEndpoint> By id; keys are for lookup only. */
    private array $endpoints = [];

    #[\Override]
    public function find(WebhookEndpointId $id): ?WebhookEndpoint
    {
        return $this->endpoints[$id->value] ?? null;
    }

    #[\Override]
    public function all(): array
    {
        $all = array_values($this->endpoints);
        usort(
            $all,
            static fn (WebhookEndpoint $a, WebhookEndpoint $b): int
                => [$a->createdAt, $a->id->value] <=> [$b->createdAt, $b->id->value],
        );

        return $all;
    }

    #[\Override]
    public function count(): int
    {
        return count($this->endpoints);
    }

    #[\Override]
    public function save(WebhookEndpoint $endpoint): void
    {
        $this->endpoints[$endpoint->id->value] = $endpoint;
    }

    #[\Override]
    public function delete(WebhookEndpointId $id): void
    {
        unset($this->endpoints[$id->value]);
    }
}
