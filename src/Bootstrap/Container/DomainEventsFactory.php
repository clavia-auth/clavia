<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\Events\Psr14DomainEvents;
use Clavia\Adapter\Secondary\Events\SubscriberListenerProvider;
use Clavia\Adapter\Secondary\Events\SynchronousEventDispatcher;
use Clavia\Application\Event\EventSubscriber;
use Clavia\Application\Port\DomainEvents;
use Clavia\Bootstrap\ConfigProvider;
use Psr\Container\ContainerInterface;

/**
 * The domain events, dispatched synchronously to every subscriber in
 * {@see ConfigProvider::EVENT_SUBSCRIBERS}.
 */
final class DomainEventsFactory
{
    public function __invoke(ContainerInterface $container): DomainEvents
    {
        $subscribers = array_map(
            static function (string $class) use ($container): EventSubscriber {
                /** @var EventSubscriber */
                return $container->get($class);
            },
            ConfigProvider::EVENT_SUBSCRIBERS,
        );

        return new Psr14DomainEvents(new SynchronousEventDispatcher(new SubscriberListenerProvider(...$subscribers)));
    }
}
