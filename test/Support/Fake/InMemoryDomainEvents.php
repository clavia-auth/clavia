<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Event\EventSubscriber;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Shared\DomainEvent;

/**
 * Domain events kept in memory, in the order dispatched, and handed synchronously to the
 * subscribers it was given — none by default, for a test about what a use case says
 * rather than what follows from it.
 */
final class InMemoryDomainEvents implements DomainEvents
{
    /** @var list<DomainEvent> */
    private array $events = [];

    /** @var list<EventSubscriber> */
    private readonly array $subscribers;

    public function __construct(EventSubscriber ...$subscribers)
    {
        $this->subscribers = array_values($subscribers);
    }

    #[\Override]
    public function dispatch(DomainEvent $event): void
    {
        $this->events[] = $event;
        foreach ($this->subscribers as $subscriber) {
            foreach ($subscriber->subscriptions() as $class => $listener) {
                if ($event instanceof $class) {
                    $listener($event);
                }
            }
        }
    }

    /**
     * Every event dispatched, oldest first.
     *
     * @return list<DomainEvent>
     */
    public function all(): array
    {
        return $this->events;
    }

    /**
     * The events of one class, oldest first.
     *
     * @template T of DomainEvent
     *
     * @param class-string<T> $class
     *
     * @return list<T>
     */
    public function ofType(string $class): array
    {
        $matching = [];
        foreach ($this->events as $event) {
            if ($event instanceof $class) {
                $matching[] = $event;
            }
        }

        return $matching;
    }
}
