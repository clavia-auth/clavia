<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Webhook\WebhookDisabledReason;
use Clavia\Domain\Webhook\WebhookEndpoint;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;
use DateTimeImmutable;

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
        $stored = $this->endpoints[$endpoint->id->value] ?? null;
        // As the database does: only switching it on or off resets the failure clock.
        $this->endpoints[$endpoint->id->value] = $stored === null || $stored->isEnabled !== $endpoint->isEnabled
            ? $endpoint
            : self::with($endpoint, $stored->failingSince, $endpoint->isEnabled, $endpoint->disabledReason);
    }

    #[\Override]
    public function recordFailure(WebhookEndpointId $id, DateTimeImmutable $now): void
    {
        $endpoint = $this->endpoints[$id->value] ?? null;
        if ($endpoint !== null && $endpoint->failingSince === null) {
            $this->endpoints[$id->value] = self::with($endpoint, $now, $endpoint->isEnabled, $endpoint->disabledReason);
        }
    }

    #[\Override]
    public function recordSuccess(WebhookEndpointId $id): void
    {
        $endpoint = $this->endpoints[$id->value] ?? null;
        if ($endpoint !== null) {
            $this->endpoints[$id->value] = self::with($endpoint, null, $endpoint->isEnabled, $endpoint->disabledReason);
        }
    }

    #[\Override]
    public function disableIfFailingSince(
        WebhookEndpointId $id,
        DateTimeImmutable $before,
        DateTimeImmutable $now,
    ): bool {
        $endpoint = $this->endpoints[$id->value] ?? null;
        if (
            $endpoint === null
            || ! $endpoint->isEnabled
            || $endpoint->failingSince === null
            || $endpoint->failingSince > $before
        ) {
            return false;
        }
        $this->endpoints[$id->value] = self::with(
            $endpoint,
            $endpoint->failingSince,
            false,
            WebhookDisabledReason::Failing,
            $now,
        );

        return true;
    }

    private static function with(
        WebhookEndpoint $endpoint,
        ?DateTimeImmutable $failingSince,
        bool $enabled,
        ?WebhookDisabledReason $reason,
        ?DateTimeImmutable $updatedAt = null,
    ): WebhookEndpoint {
        return WebhookEndpoint::reconstitute(
            $endpoint->id,
            $endpoint->url,
            $endpoint->description,
            $endpoint->events,
            $enabled,
            $endpoint->sealedSecret,
            $endpoint->sealedPreviousSecret,
            $endpoint->previousSecretUntil,
            $endpoint->createdAt,
            $updatedAt ?? $endpoint->updatedAt,
            $failingSince,
            $reason,
        );
    }

    #[\Override]
    public function delete(WebhookEndpointId $id): void
    {
        unset($this->endpoints[$id->value]);
    }
}
