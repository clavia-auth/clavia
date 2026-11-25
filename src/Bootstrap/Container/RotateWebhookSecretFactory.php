<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Webhooks\RotateWebhookSecret;
use Clavia\Application\Management\Webhooks\WebhookSecrets;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Webhook\WebhookEndpointRepository;
use Psr\Container\ContainerInterface;

final class RotateWebhookSecretFactory
{
    public function __invoke(ContainerInterface $container): RotateWebhookSecret
    {
        /** @var WebhookEndpointRepository $endpoints */
        $endpoints = $container->get(WebhookEndpointRepository::class);
        /** @var WebhookSecrets $secrets */
        $secrets = $container->get(WebhookSecrets::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new RotateWebhookSecret($endpoints, $secrets, $clock, $events);
    }
}
