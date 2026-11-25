<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Persistence;

use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbAuditLog;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbWebhookDeliveryRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbWebhookEndpointRepository;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Webhook\WebhookDeliveryRepository;
use Clavia\Domain\Webhook\WebhookEndpointRepository;
use ClaviaTest\Support\Contract\WebhookDeliveryRepositoryContract;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestStorage;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditQuery;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Webhook\EventFilter;
use DateTimeImmutable;

final class PhpDbWebhookDeliveryRepositoryTest extends IntegrationTestCase
{
    use WebhookDeliveryRepositoryContract;

    #[\Override]
    protected function auditLog(): AuditLog
    {
        return new PhpDbAuditLog(TestStorage::database());
    }

    #[\Override]
    protected function webhookEndpoints(): WebhookEndpointRepository
    {
        return new PhpDbWebhookEndpointRepository(TestStorage::database());
    }

    #[\Override]
    protected function webhookDeliveries(): WebhookDeliveryRepository
    {
        return new PhpDbWebhookDeliveryRepository(TestStorage::database());
    }

    public function testAPurgedEventTakesItsDeliveriesAlong(): void
    {
        $this->anEndpoint(1, EventFilter::all());
        $this->anEvent(1, AuditEventType::UserCreated);
        $this->webhookDeliveries()->enqueueFor(
            $this->auditLog()->page(new AuditQuery(), PageRequest::of(1, 1))->items[0],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        self::assertSame(1, (int) TestStorage::database()->fetchValue('SELECT count(*) FROM webhook_deliveries'));

        $this->auditLog()->purgeBefore(new DateTimeImmutable('2026-02-01T00:00:00Z'));

        self::assertSame(0, (int) TestStorage::database()->fetchValue('SELECT count(*) FROM webhook_deliveries'));
    }
}
