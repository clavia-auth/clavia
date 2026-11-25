<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditEventId;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Audit\AuditQuery;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use DateTimeImmutable;

final class InMemoryAuditLog implements AuditLog
{
    /** @var list<AuditEvent> In the order appended. */
    private array $events = [];

    #[\Override]
    public function find(AuditEventId $id): ?AuditEvent
    {
        foreach ($this->events as $event) {
            if ($event->id->equals($id)) {
                return $event;
            }
        }

        return null;
    }

    #[\Override]
    public function append(AuditEvent $event): void
    {
        $this->events[] = $event;
    }

    #[\Override]
    public function page(AuditQuery $query, PageRequest $request): Page
    {
        $matching = array_values(array_filter($this->events, static fn (AuditEvent $event): bool => self::matches(
            $event,
            $query,
        )));
        usort($matching, static fn (AuditEvent $a, AuditEvent $b): int => [$b->occurredAt, $b->id->value]
            <=> [$a->occurredAt, $a->id->value]);

        return new Page(array_slice($matching, $request->offset(), $request->perPage), count($matching), $request);
    }

    #[\Override]
    public function purgeBefore(DateTimeImmutable $before): int
    {
        $kept = array_values(array_filter($this->events, static fn (AuditEvent $e): bool => $e->occurredAt >= $before));
        $removed = count($this->events) - count($kept);
        assert($removed >= 0);
        $this->events = $kept;

        return $removed;
    }

    /**
     * Every event, oldest first — for a test to look at what a use case recorded.
     *
     * @return list<AuditEvent>
     */
    public function all(): array
    {
        return $this->events;
    }

    /**
     * The events of these types, oldest first.
     *
     * @return list<AuditEvent>
     */
    public function ofType(AuditEventType ...$types): array
    {
        return array_values(array_filter($this->events, static fn (AuditEvent $e): bool => in_array(
            $e->type,
            $types,
            true,
        )));
    }

    private static function matches(AuditEvent $event, AuditQuery $query): bool
    {
        return ($query->types === [] || in_array($event->type, $query->types, true))
            && ($query->actorUserId === null || ($event->actor->userId?->equals($query->actorUserId) ?? false))
            && ($query->clientId === null || ($event->actor->clientId?->equals($query->clientId) ?? false))
            && ($query->target === null || ($event->target?->type === $query->target->type
                && $event->target->id === $query->target->id))
            && ($query->outcome === null || $event->outcome === $query->outcome)
            && ($query->since === null || $event->occurredAt >= $query->since)
            && ($query->until === null || $event->occurredAt < $query->until);
    }
}
