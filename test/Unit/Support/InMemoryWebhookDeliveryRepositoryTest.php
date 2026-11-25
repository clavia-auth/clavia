<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Webhook\WebhookDeliveryRepository;
use Clavia\Domain\Webhook\WebhookEndpointRepository;
use ClaviaTest\Support\Contract\WebhookDeliveryRepositoryContract;
use ClaviaTest\Support\Fake\InMemoryAuditLog;
use ClaviaTest\Support\Fake\InMemoryWebhookDeliveryRepository;
use ClaviaTest\Support\Fake\InMemoryWebhookEndpointRepository;
use PHPUnit\Framework\TestCase;

final class InMemoryWebhookDeliveryRepositoryTest extends TestCase
{
    use WebhookDeliveryRepositoryContract;

    private InMemoryAuditLog $log;
    private InMemoryWebhookEndpointRepository $endpoints;
    private InMemoryWebhookDeliveryRepository $deliveries;

    #[\Override]
    protected function setUp(): void
    {
        $this->log = new InMemoryAuditLog();
        $this->endpoints = new InMemoryWebhookEndpointRepository();
        $this->deliveries = new InMemoryWebhookDeliveryRepository($this->endpoints);
    }

    #[\Override]
    protected function auditLog(): AuditLog
    {
        return $this->log;
    }

    #[\Override]
    protected function webhookEndpoints(): WebhookEndpointRepository
    {
        return $this->endpoints;
    }

    #[\Override]
    protected function webhookDeliveries(): WebhookDeliveryRepository
    {
        return $this->deliveries;
    }
}
