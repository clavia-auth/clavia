<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Webhooks\TestWebhook;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Webhook\WebhookEndpointRepository;
use Psr\Container\ContainerInterface;

final class TestWebhookFactory
{
    public function __invoke(ContainerInterface $container): TestWebhook
    {
        /** @var WebhookEndpointRepository $endpoints */
        $endpoints = $container->get(WebhookEndpointRepository::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new TestWebhook($endpoints, $transactions, $events);
    }
}
