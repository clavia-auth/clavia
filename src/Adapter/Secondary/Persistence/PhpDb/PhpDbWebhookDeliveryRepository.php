<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditEventId;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\TargetType;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Webhook\DeliveryFailure;
use Clavia\Domain\Webhook\WebhookDelivery;
use Clavia\Domain\Webhook\WebhookDeliveryId;
use Clavia\Domain\Webhook\WebhookDeliveryRepository;
use Clavia\Domain\Webhook\WebhookDeliveryStatus;
use Clavia\Domain\Webhook\WebhookEndpointId;
use DateTimeImmutable;

/**
 * The webhook outbox in `webhook_deliveries`. Queuing is one `INSERT … SELECT` over the enabled
 * endpoints whose filter holds the event's type (or `*`); claiming takes endpoints with
 * `FOR UPDATE SKIP LOCKED`, so two workers never share one.
 *
 * @psalm-type DeliveryRow = array{id: string, endpoint_id: string, audit_event_id: string, event_type: string,
 *     status: string,
 *     attempts: int, next_attempt_at: string, last_status_code: int|null, last_duration_ms: int|null,
 *     last_failure: string|null, created_at: string, ended_at: string|null}
 */
final readonly class PhpDbWebhookDeliveryRepository implements WebhookDeliveryRepository
{
    private const string COLUMNS = 'id, endpoint_id, audit_event_id, event_type, status, attempts, next_attempt_at, '
        . 'last_status_code, last_duration_ms, last_failure, created_at, ended_at';

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function enqueueFor(AuditEvent $event, DateTimeImmutable $now): int
    {
        return max(0, $this->database->execute(
            <<<'SQL'
                INSERT INTO webhook_deliveries (id, endpoint_id, audit_event_id, event_type, status, attempts,
                    next_attempt_at, created_at)
                SELECT gen_random_uuid(), e.id, :event, :type, 'pending', 0, :due, :created
                FROM webhook_endpoints e
                WHERE e.is_enabled
                    AND CASE WHEN CAST(:kind AS text) = CAST(:tested AS text)
                        THEN CAST(e.id AS text) = CAST(:target AS text)
                        ELSE e.events @> '["*"]'::jsonb OR e.events @> jsonb_build_array(CAST(:listened AS text))
                    END
                SQL,
            [
                'event' => $event->id->value,
                'type' => $event->type->value,
                'kind' => $event->type->value,
                'listened' => $event->type->value,
                'tested' => AuditEventType::WebhookTested->value,
                'target' => $event->target?->type === TargetType::Webhook ? $event->target->id : '',
                'due' => Timestamp::toDatabase($now),
                'created' => Timestamp::toDatabase($now),
            ],
        ));
    }

    #[\Override]
    public function claimEndpoints(DateTimeImmutable $now, DateTimeImmutable $until, int $limit): array
    {
        /** @var list<array{id: string}> $rows */
        $rows = $this->database->fetchAll(
            <<<'SQL'
                UPDATE webhook_endpoints SET delivering_until = :until
                WHERE id IN (
                    SELECT e.id FROM webhook_endpoints e
                    WHERE (e.delivering_until IS NULL OR e.delivering_until < :free)
                        AND EXISTS (
                            SELECT 1 FROM webhook_deliveries d
                            WHERE d.endpoint_id = e.id AND d.status = 'pending' AND d.next_attempt_at <= :due
                        )
                    ORDER BY e.created_at, e.id
                    LIMIT :limit
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING id
                SQL,
            [
                'until' => Timestamp::toDatabase($until),
                'free' => Timestamp::toDatabase($now),
                'due' => Timestamp::toDatabase($now),
                'limit' => $limit,
            ],
        );

        return array_map(static fn (array $row): WebhookEndpointId => WebhookEndpointId::fromString($row['id']), $rows);
    }

    #[\Override]
    public function due(WebhookEndpointId $endpoint, DateTimeImmutable $now, int $limit): array
    {
        /** @var list<DeliveryRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . " FROM webhook_deliveries WHERE endpoint_id = :endpoint AND status = 'pending' "
            . 'AND next_attempt_at <= :now ORDER BY created_at, id LIMIT :limit',
            ['endpoint' => $endpoint->value, 'now' => Timestamp::toDatabase($now), 'limit' => $limit],
        );

        return array_map(self::hydrate(...), $rows);
    }

    #[\Override]
    public function save(WebhookDelivery $delivery): void
    {
        $this->database->execute(
            <<<'SQL'
                UPDATE webhook_deliveries SET status = :status, attempts = :attempts, next_attempt_at = :next,
                    last_status_code = :code, last_duration_ms = :duration, last_failure = :failure,
                    ended_at = :ended
                WHERE id = :id
                SQL,
            [
                'id' => $delivery->id->value,
                'status' => $delivery->status->value,
                'attempts' => $delivery->attempts,
                'next' => Timestamp::toDatabase($delivery->nextAttemptAt),
                'code' => $delivery->lastStatusCode,
                'duration' => $delivery->lastDurationMs,
                'failure' => $delivery->lastFailure?->value,
                'ended' => $delivery->endedAt === null ? null : Timestamp::toDatabase($delivery->endedAt),
            ],
        );
    }

    #[\Override]
    public function page(WebhookEndpointId $endpoint, PageRequest $request): Page
    {
        /** @var int|string $total */
        $total = $this->database->fetchValue(
            'SELECT count(*) FROM webhook_deliveries WHERE endpoint_id = :endpoint',
            ['endpoint' => $endpoint->value],
        );
        /** @var list<DeliveryRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM webhook_deliveries WHERE endpoint_id = :endpoint '
            . 'ORDER BY created_at DESC, id DESC LIMIT :limit OFFSET :offset',
            ['endpoint' => $endpoint->value, 'limit' => $request->perPage, 'offset' => $request->offset()],
        );

        return new Page(array_map(self::hydrate(...), $rows), max(0, (int) $total), $request);
    }

    #[\Override]
    public function release(WebhookEndpointId $endpoint): void
    {
        $this->database->execute(
            'UPDATE webhook_endpoints SET delivering_until = NULL WHERE id = :id',
            ['id' => $endpoint->value],
        );
    }

    #[\Override]
    public function purgeEndedBefore(DateTimeImmutable $before): int
    {
        return max(0, $this->database->execute(
            'DELETE FROM webhook_deliveries WHERE ended_at < :before',
            ['before' => Timestamp::toDatabase($before)],
        ));
    }

    /** @param DeliveryRow $row */
    private static function hydrate(array $row): WebhookDelivery
    {
        return WebhookDelivery::reconstitute(
            WebhookDeliveryId::fromString($row['id']),
            WebhookEndpointId::fromString($row['endpoint_id']),
            AuditEventId::fromString($row['audit_event_id']),
            AuditEventType::from($row['event_type']),
            WebhookDeliveryStatus::from($row['status']),
            $row['attempts'],
            Timestamp::fromDatabase($row['next_attempt_at']),
            $row['last_status_code'],
            $row['last_duration_ms'],
            $row['last_failure'] === null ? null : DeliveryFailure::from($row['last_failure']),
            Timestamp::fromDatabase($row['created_at']),
            $row['ended_at'] === null ? null : Timestamp::fromDatabase($row['ended_at']),
        );
    }
}
