<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Event\EventSubscriber;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\Event\ClientSecretRotated;
use ClaviaTest\Support\Contract\DomainEventsContract;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use PHPUnit\Framework\TestCase;

final class InMemoryDomainEventsTest extends TestCase
{
    use DomainEventsContract;

    public function testItKeepsWhatWasDispatchedInOrder(): void
    {
        $events = new InMemoryDomainEvents();
        $first = new ClientSecretRotated(ClientId::fromString('one'));
        $second = new ClientSecretRotated(ClientId::fromString('two'));

        $events->dispatch($first);
        $events->dispatch($second);

        self::assertSame([$first, $second], $events->all());
        self::assertSame([$first, $second], $events->ofType(ClientSecretRotated::class));
    }

    #[\Override]
    protected function domainEvents(EventSubscriber ...$subscribers): DomainEvents
    {
        return new InMemoryDomainEvents(...$subscribers);
    }
}
