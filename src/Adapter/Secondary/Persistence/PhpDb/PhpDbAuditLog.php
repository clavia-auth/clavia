<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Audit\ActorKind;
use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditEventId;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Audit\AuditQuery;
use Clavia\Domain\Audit\AuditTarget;
use Clavia\Domain\Audit\Outcome;
use Clavia\Domain\Audit\TargetType;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use DateTimeImmutable;

/**
 * @psalm-type AuditEventRow = array{id: string, type: string, occurred_at: string, outcome: string,
 *     actor_kind: string, actor_user_id: string|null, actor_client_id: string|null,
 *     actor_provisioning_token_id: string|null, target_type: string|null,
 *     target_id: string|null, details: string, client_address: string|null, user_agent: string|null}
 *
 * The audit trail in `audit_events` — append-only, as the table's trigger enforces.
 *
 * Written through the one {@see Database}, so an event recorded inside a use case's
 * transaction commits and rolls back with the change it describes.
 */
final readonly class PhpDbAuditLog implements AuditLog
{
    private const string COLUMNS = 'id, type, occurred_at, outcome, actor_kind, actor_user_id, actor_client_id, '
        . 'actor_provisioning_token_id, target_type, target_id, details::text AS details, client_address, user_agent';

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function find(AuditEventId $id): ?AuditEvent
    {
        /** @var AuditEventRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM audit_events WHERE id = :id',
            ['id' => $id->value],
        );

        return $row === null ? null : self::hydrate($row);
    }

    #[\Override]
    public function append(AuditEvent $event): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO audit_events (
                    id, type, occurred_at, outcome, actor_kind, actor_user_id, actor_client_id,
                    actor_provisioning_token_id, target_type, target_id, details, client_address, user_agent
                ) VALUES (
                    :id, :type, :occurred_at, :outcome, :actor_kind, :actor_user_id, :actor_client_id,
                    :actor_provisioning_token_id, :target_type, :target_id, CAST(:details AS jsonb),
                    :client_address, :user_agent
                )
                SQL,
            [
                'id' => $event->id->value,
                'type' => $event->type->value,
                'occurred_at' => Timestamp::toDatabase($event->occurredAt),
                'outcome' => $event->outcome->value,
                'actor_kind' => $event->actor->kind->value,
                'actor_user_id' => $event->actor->userId?->value,
                'actor_client_id' => $event->actor->clientId?->value,
                'actor_provisioning_token_id' => $event->actor->provisioningTokenId?->value,
                'target_type' => $event->target?->type->value,
                'target_id' => $event->target?->id,
                'details' => json_encode((object) $event->details, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
                'client_address' => $event->clientAddress,
                'user_agent' => $event->userAgent,
            ],
        );
    }

    #[\Override]
    public function page(AuditQuery $query, PageRequest $request): Page
    {
        [$where, $parameters] = self::where($query);

        /** @var int|string $total */
        $total = $this->database->fetchValue('SELECT count(*) FROM audit_events ' . $where, $parameters);
        /** @var list<AuditEventRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM audit_events ' . $where
            . ' ORDER BY occurred_at DESC, id DESC LIMIT :limit OFFSET :offset',
            $parameters + ['limit' => $request->perPage, 'offset' => $request->offset()],
        );

        return new Page(array_map(self::hydrate(...), $rows), max(0, (int) $total), $request);
    }

    #[\Override]
    public function purgeBefore(DateTimeImmutable $before): int
    {
        return max(0, $this->database->execute(
            'DELETE FROM audit_events WHERE occurred_at < :before',
            ['before' => Timestamp::toDatabase($before)],
        ));
    }

    /**
     * The conditions of `$query` as SQL written here — column names and placeholders only —
     * and the values bound to them.
     *
     * @return array{string, array<string, string>}
     */
    private static function where(AuditQuery $query): array
    {
        $conditions = [];
        $parameters = [];

        if ($query->types !== []) {
            $placeholders = [];
            foreach ($query->types as $index => $type) {
                $placeholders[] = ':type_' . $index;
                $parameters['type_' . $index] = $type->value;
            }
            $conditions[] = 'type IN (' . implode(', ', $placeholders) . ')';
        }
        if ($query->actorUserId !== null) {
            $conditions[] = 'actor_user_id = :actor_user_id';
            $parameters['actor_user_id'] = $query->actorUserId->value;
        }
        if ($query->clientId !== null) {
            $conditions[] = 'actor_client_id = :actor_client_id';
            $parameters['actor_client_id'] = $query->clientId->value;
        }
        if ($query->target !== null) {
            $conditions[] = 'target_type = :target_type AND target_id = :target_id';
            $parameters['target_type'] = $query->target->type->value;
            $parameters['target_id'] = $query->target->id;
        }
        if ($query->outcome !== null) {
            $conditions[] = 'outcome = :outcome';
            $parameters['outcome'] = $query->outcome->value;
        }
        if ($query->since !== null) {
            $conditions[] = 'occurred_at >= :since';
            $parameters['since'] = Timestamp::toDatabase($query->since);
        }
        if ($query->until !== null) {
            $conditions[] = 'occurred_at < :until';
            $parameters['until'] = Timestamp::toDatabase($query->until);
        }

        return [$conditions === [] ? '' : 'WHERE ' . implode(' AND ', $conditions), $parameters];
    }

    /**
     * @param AuditEventRow $row
     */
    private static function hydrate(array $row): AuditEvent
    {
        /** @var array<string, string|int|bool|list<string>> $details */
        $details = Jsonb::decodeObject($row['details']);

        return AuditEvent::record(
            AuditEventId::fromString($row['id']),
            AuditEventType::from($row['type']),
            Timestamp::fromDatabase($row['occurred_at']),
            Actor::reconstitute(
                ActorKind::from($row['actor_kind']),
                $row['actor_user_id'] === null ? null : UserId::fromString($row['actor_user_id']),
                $row['actor_client_id'] === null ? null : ClientId::fromString($row['actor_client_id']),
                $row['actor_provisioning_token_id'] === null
                    ? null
                    : ProvisioningTokenId::fromString($row['actor_provisioning_token_id']),
            ),
            $row['target_type'] === null || $row['target_id'] === null
                ? null
                : AuditTarget::of(TargetType::from($row['target_type']), $row['target_id']),
            Outcome::from($row['outcome']),
            $details,
            $row['client_address'],
            $row['user_agent'],
        );
    }
}
