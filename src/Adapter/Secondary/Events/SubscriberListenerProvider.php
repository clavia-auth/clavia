<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Events;

use Clavia\Application\Event\EventSubscriber;
use Closure;
use Psr\EventDispatcher\ListenerProviderInterface;

/**
 * The listeners for an event (PSR-14): every subscription whose class the event is an
 * instance of, in the order the subscribers were given, then the order each lists them.
 */
final readonly class SubscriberListenerProvider implements ListenerProviderInterface
{
    /** @var list<array{class-string, Closure}> */
    private array $subscriptions;

    public function __construct(EventSubscriber ...$subscribers)
    {
        $subscriptions = [];
        foreach ($subscribers as $subscriber) {
            foreach ($subscriber->subscriptions() as $class => $listener) {
                $subscriptions[] = [$class, $listener];
            }
        }
        $this->subscriptions = $subscriptions;
    }

    /**
     * @return iterable<Closure>
     */
    #[\Override]
    public function getListenersForEvent(object $event): iterable
    {
        foreach ($this->subscriptions as [$class, $listener]) {
            if ($event instanceof $class) {
                yield $listener;
            }
        }
    }
}
