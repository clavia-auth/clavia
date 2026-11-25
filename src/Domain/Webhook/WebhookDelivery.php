<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Webhook;

use Clavia\Domain\Audit\AuditEventId;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Shared\RandomSource;
use DateTimeImmutable;
use LogicException;

/**
 * One audit event to one endpoint: pending until a 2xx comes back, retried on {@see RetrySchedule},
 * abandoned when the retries run out or it can no longer be sent. It keeps of each attempt only
 * its status code, how long it took and why it failed.
 */
final readonly class WebhookDelivery
{
    private function __construct(
        public WebhookDeliveryId $id,
        public WebhookEndpointId $endpointId,
        public AuditEventId $auditEventId,
        public AuditEventType $eventType,
        public WebhookDeliveryStatus $status,
        public int $attempts,
        public DateTimeImmutable $nextAttemptAt,
        public ?int $lastStatusCode,
        public ?int $lastDurationMs,
        public ?DeliveryFailure $lastFailure,
        public DateTimeImmutable $createdAt,
        public ?DateTimeImmutable $endedAt,
    ) {
    }

    /** Rebuild a delivery from storage. */
    public static function reconstitute(
        WebhookDeliveryId $id,
        WebhookEndpointId $endpointId,
        AuditEventId $auditEventId,
        AuditEventType $eventType,
        WebhookDeliveryStatus $status,
        int $attempts,
        DateTimeImmutable $nextAttemptAt,
        ?int $lastStatusCode,
        ?int $lastDurationMs,
        ?DeliveryFailure $lastFailure,
        DateTimeImmutable $createdAt,
        ?DateTimeImmutable $endedAt,
    ): self {
        return new self(
            $id,
            $endpointId,
            $auditEventId,
            $eventType,
            $status,
            $attempts,
            $nextAttemptAt,
            $lastStatusCode,
            $lastDurationMs,
            $lastFailure,
            $createdAt,
            $endedAt,
        );
    }

    public function succeeded(int $statusCode, int $durationMs, DateTimeImmutable $now): self
    {
        $this->assertPending();

        return clone($this, [
            'status' => WebhookDeliveryStatus::Succeeded,
            'attempts' => $this->attempts + 1,
            'lastStatusCode' => $statusCode,
            'lastDurationMs' => $durationMs,
            'lastFailure' => null,
            'endedAt' => $now,
        ]);
    }

    /** An attempt that failed: tried again on the schedule, or abandoned after the last. */
    public function failed(
        DeliveryFailure $why,
        ?int $statusCode,
        int $durationMs,
        DateTimeImmutable $now,
        RandomSource $random,
    ): self {
        $this->assertPending();
        $attempts = max(1, $this->attempts + 1);
        $delay = RetrySchedule::delayAfter($attempts, $random);

        return clone($this, [
            'status' => $delay === null ? WebhookDeliveryStatus::Abandoned : WebhookDeliveryStatus::Pending,
            'attempts' => $attempts,
            'nextAttemptAt' => $delay === null ? $this->nextAttemptAt : $now->modify(sprintf('+%d seconds', $delay)),
            'lastStatusCode' => $statusCode,
            'lastDurationMs' => $durationMs,
            'lastFailure' => $why,
            'endedAt' => $delay === null ? $now : null,
        ]);
    }

    /** Given up on without an attempt: the endpoint is off, or the event is gone. */
    public function abandoned(DeliveryFailure $why, DateTimeImmutable $now): self
    {
        $this->assertPending();

        return clone($this, ['status' => WebhookDeliveryStatus::Abandoned, 'lastFailure' => $why, 'endedAt' => $now]);
    }

    private function assertPending(): void
    {
        if ($this->status !== WebhookDeliveryStatus::Pending) {
            throw new LogicException('A delivery that ended is not attempted again.');
        }
    }
}
