<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Events;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\EventDispatcher\ListenerProviderInterface;
use Psr\EventDispatcher\StoppableEventInterface;

/**
 * A PSR-14 dispatcher that calls each listener in turn, in the caller's process and
 * transaction, and lets whatever a listener throws reach the caller.
 *
 * A stoppable event stops being passed on once it says so (PSR-14 §Dispatcher); Clavia's
 * domain events are never stoppable, but the interface is honoured for any other.
 */
final readonly class SynchronousEventDispatcher implements EventDispatcherInterface
{
    public function __construct(private ListenerProviderInterface $listeners)
    {
    }

    #[\Override]
    public function dispatch(object $event): object
    {
        /** @var iterable<callable(object): mixed> $listeners PSR-14: each takes the event. */
        $listeners = $this->listeners->getListenersForEvent($event);
        foreach ($listeners as $listener) {
            if ($event instanceof StoppableEventInterface && $event->isPropagationStopped()) {
                break;
            }
            $listener($event);
        }

        return $event;
    }
}
