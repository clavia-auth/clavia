<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\SecretCipher;
use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Port\WebhookSender;
use Clavia\Application\Webhooks\DeliverWebhooks;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Webhook\WebhookDeliveryRepository;
use Clavia\Domain\Webhook\WebhookEndpointRepository;
use Psr\Container\ContainerInterface;

final class DeliverWebhooksFactory
{
    public function __invoke(ContainerInterface $container): DeliverWebhooks
    {
        /** @var WebhookEndpointRepository $endpoints */
        $endpoints = $container->get(WebhookEndpointRepository::class);
        /** @var WebhookDeliveryRepository $deliveries */
        $deliveries = $container->get(WebhookDeliveryRepository::class);
        /** @var AuditLog $log */
        $log = $container->get(AuditLog::class);
        /** @var SecretCipher $cipher */
        $cipher = $container->get(SecretCipher::class);
        /** @var WebhookSender $sender */
        $sender = $container->get(WebhookSender::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new DeliverWebhooks(
            $endpoints,
            $deliveries,
            $log,
            $cipher,
            $sender,
            $random,
            $clock,
            $transactions,
            $events,
        );
    }
}
