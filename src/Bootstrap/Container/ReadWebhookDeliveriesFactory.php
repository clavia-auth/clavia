<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Webhooks\ReadWebhookDeliveries;
use Clavia\Domain\Webhook\WebhookDeliveryRepository;
use Clavia\Domain\Webhook\WebhookEndpointRepository;
use Psr\Container\ContainerInterface;

final class ReadWebhookDeliveriesFactory
{
    public function __invoke(ContainerInterface $container): ReadWebhookDeliveries
    {
        /** @var WebhookEndpointRepository $endpoints */
        $endpoints = $container->get(WebhookEndpointRepository::class);
        /** @var WebhookDeliveryRepository $deliveries */
        $deliveries = $container->get(WebhookDeliveryRepository::class);

        return new ReadWebhookDeliveries($endpoints, $deliveries);
    }
}
