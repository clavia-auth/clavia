<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Webhook;

use Clavia\Domain\Audit\AuditEvent;
use DateTimeImmutable;

/**
 * The outbox: one pending delivery per enabled endpoint listening to an audit event, written in the
 * transaction that records the event, so a rolled-back change sends nothing and a committed one is
 * never lost (docs/design/webhooks.md §2, "Reliability").
 */
interface WebhookDeliveryRepository
{
    /**
     * Queue the event for every enabled endpoint whose filter matches it, due now.
     *
     * @return int How many deliveries were queued.
     */
    public function enqueueFor(AuditEvent $event, DateTimeImmutable $now): int;

    /**
     * Claim up to `$limit` endpoints that have a delivery due and no worker on them, until `$until`:
     * a worker sends an endpoint's deliveries one at a time, so a receiver never has two in flight.
     * A worker that dies leaves its claim to lapse.
     *
     * @return list<WebhookEndpointId>
     */
    public function claimEndpoints(DateTimeImmutable $now, DateTimeImmutable $until, int $limit): array;

    /** @return list<WebhookDelivery> An endpoint's due deliveries, oldest first. */
    public function due(WebhookEndpointId $endpoint, DateTimeImmutable $now, int $limit): array;

    public function save(WebhookDelivery $delivery): void;

    /** Let another worker take the endpoint. */
    public function release(WebhookEndpointId $endpoint): void;

    /** Delete the deliveries that ended before `$before`. @return int How many. */
    public function purgeEndedBefore(DateTimeImmutable $before): int;
}
