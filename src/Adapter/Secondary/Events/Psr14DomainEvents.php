<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Events;

use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Shared\DomainEvent;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * The `DomainEvents` port on any PSR-14 dispatcher — {@see SynchronousEventDispatcher}
 * here. Swapping in another dispatcher is a composition-root change, as long as it stays
 * synchronous: the port promises that every subscriber has run when `dispatch()` returns.
 */
final readonly class Psr14DomainEvents implements DomainEvents
{
    public function __construct(private EventDispatcherInterface $dispatcher)
    {
    }

    #[\Override]
    public function dispatch(DomainEvent $event): void
    {
        $this->dispatcher->dispatch($event);
    }
}
