<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Event\EventSubscriber;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\Event\ClientSecretRotated;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\Event\ConnectionDeleted;
use Clavia\Domain\Shared\DomainEvent;
use Closure;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;

/**
 * What the `DomainEvents` port promises, for the in-memory double and the PSR-14 adapter
 * alike: every subscriber listening has run, in order, when `dispatch()` returns, and a
 * failure reaches the caller.
 */
trait DomainEventsContract
{
    /** @var list<string> What the subscribers saw, as "subscriber:event". */
    private array $seen = [];

    abstract protected function domainEvents(EventSubscriber ...$subscribers): DomainEvents;

    #[Test]
    public function everySubscriberListeningRunsInTheOrderGiven(): void
    {
        $events = $this->domainEvents(
            $this->subscriber('first', [ClientSecretRotated::class]),
            $this->subscriber('second', [ConnectionDeleted::class, ClientSecretRotated::class]),
        );

        $events->dispatch(new ClientSecretRotated(ClientId::fromString('spa')));

        self::assertSame(['first:ClientSecretRotated', 'second:ClientSecretRotated'], $this->seen);
    }

    #[Test]
    public function anEventNobodyListensForGoesNowhere(): void
    {
        $events = $this->domainEvents($this->subscriber('only', [ClientSecretRotated::class]));

        $events->dispatch(new ConnectionDeleted(ConnectionName::defaultPool()));

        self::assertSame([], $this->seen);
    }

    #[Test]
    public function aSubscriptionToAnInterfaceHearsEveryEventImplementingIt(): void
    {
        $events = $this->domainEvents($this->subscriber('all', [DomainEvent::class]));

        $events->dispatch(new ClientSecretRotated(ClientId::fromString('spa')));
        $events->dispatch(new ConnectionDeleted(ConnectionName::defaultPool()));

        self::assertSame(['all:ClientSecretRotated', 'all:ConnectionDeleted'], $this->seen);
    }

    #[Test]
    public function aFailingSubscriberFailsTheDispatchAndStopsWhatFollows(): void
    {
        $failing = new class implements EventSubscriber {
            #[\Override]
            public function subscriptions(): array
            {
                return [ClientSecretRotated::class => static function (): never {
                    throw new RuntimeException('The audit trail is unreachable.');
                }];
            }
        };
        $events = $this->domainEvents($failing, $this->subscriber('after', [ClientSecretRotated::class]));

        try {
            $events->dispatch(new ClientSecretRotated(ClientId::fromString('spa')));
            self::fail('The failure was swallowed.');
        } catch (RuntimeException $failure) {
            self::assertSame('The audit trail is unreachable.', $failure->getMessage());
        }
        self::assertSame([], $this->seen);
    }

    /**
     * A subscriber that notes, under `$name`, every event of the classes it listens to.
     *
     * @param list<class-string<DomainEvent>> $classes
     */
    private function subscriber(string $name, array $classes): EventSubscriber
    {
        $note = function (DomainEvent $event) use ($name): void {
            $this->seen[] = $name . ':' . new \ReflectionClass($event)->getShortName();
        };

        return new class ($classes, $note) implements EventSubscriber {
            /** @param list<class-string<DomainEvent>> $classes */
            public function __construct(private readonly array $classes, private readonly Closure $note)
            {
            }

            #[\Override]
            public function subscriptions(): array
            {
                return array_fill_keys($this->classes, $this->note);
            }
        };
    }
}
