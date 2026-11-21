<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Events;

use Clavia\Adapter\Secondary\Events\Psr14DomainEvents;
use Clavia\Adapter\Secondary\Events\SubscriberListenerProvider;
use Clavia\Adapter\Secondary\Events\SynchronousEventDispatcher;
use Clavia\Application\Event\EventSubscriber;
use Clavia\Application\Port\DomainEvents;
use ClaviaTest\Support\Contract\DomainEventsContract;
use Closure;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\ListenerProviderInterface;
use Psr\EventDispatcher\StoppableEventInterface;

final class Psr14DomainEventsTest extends TestCase
{
    use DomainEventsContract;

    public function testAStoppableEventStopsBeingPassedOnOnceItSaysSo(): void
    {
        $event = new class implements StoppableEventInterface {
            /** @var list<string> */
            public array $heard = [];

            #[\Override]
            public function isPropagationStopped(): bool
            {
                return $this->heard !== [];
            }
        };
        $listeners = new class ([
            static function () use ($event): void {
                $event->heard[] = 'first';
            },
            static function () use ($event): void {
                $event->heard[] = 'second';
            },
        ]) implements ListenerProviderInterface {
            /** @param list<Closure> $listeners */
            public function __construct(private readonly array $listeners)
            {
            }

            #[\Override]
            public function getListenersForEvent(object $event): iterable
            {
                return $this->listeners;
            }
        };

        $returned = new SynchronousEventDispatcher($listeners)->dispatch($event);

        self::assertSame($event, $returned);
        self::assertSame(['first'], $event->heard);
    }

    #[\Override]
    protected function domainEvents(EventSubscriber ...$subscribers): DomainEvents
    {
        return new Psr14DomainEvents(new SynchronousEventDispatcher(new SubscriberListenerProvider(...$subscribers)));
    }
}
