<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Authorization\FeedEntry;
use Clavia\Domain\Authorization\FeedSubject;
use Clavia\Domain\Authorization\IdentityFeedOutbox;
use Clavia\Domain\ResourceServer\ResourceServerId;
use DateTimeImmutable;

/**
 * The identity feed's outbox in `fga_outbox`. Queuing is an `INSERT … ON CONFLICT` on the API and
 * the subject, so a subject waiting already is due now at its next generation; claiming takes rows
 * with `FOR UPDATE SKIP LOCKED` and marks them claimed for a while, so two workers never send the
 * same one and no transaction stays open while the engine is called.
 *
 * @psalm-type EntryRow = array{id: int|string, resource_server_id: string, subject: string,
 *     generation: int|string, attempts: int|string}
 */
final readonly class PhpDbIdentityFeedOutbox implements IdentityFeedOutbox
{
    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function enqueue(ResourceServerId $api, array $subjects, DateTimeImmutable $now): void
    {
        foreach ($subjects as $subject) {
            $this->database->execute(
                <<<'SQL'
                    INSERT INTO fga_outbox (resource_server_id, subject, next_attempt_at, created_at)
                    VALUES (:api, :subject, :now, :now)
                    ON CONFLICT (resource_server_id, subject) DO UPDATE SET
                        generation = fga_outbox.generation + 1,
                        next_attempt_at = LEAST(fga_outbox.next_attempt_at, EXCLUDED.next_attempt_at)
                    SQL,
                ['api' => $api->value, 'subject' => $subject->toString(), 'now' => Timestamp::toDatabase($now)],
            );
        }
    }

    #[\Override]
    public function claim(DateTimeImmutable $now, DateTimeImmutable $until, int $limit): array
    {
        /** @var list<EntryRow> $rows */
        $rows = $this->database->fetchAll(
            <<<'SQL'
                UPDATE fga_outbox SET claimed_until = :until
                WHERE id IN (
                    SELECT id FROM fga_outbox
                    WHERE next_attempt_at <= :due AND (claimed_until IS NULL OR claimed_until < :free)
                    ORDER BY next_attempt_at, id
                    LIMIT :limit
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING id, resource_server_id, subject, generation, attempts
                SQL,
            [
                'until' => Timestamp::toDatabase($until),
                'due' => Timestamp::toDatabase($now),
                'free' => Timestamp::toDatabase($now),
                'limit' => $limit,
            ],
        );
        $entries = array_map(self::hydrate(...), $rows);
        usort($entries, static fn (FeedEntry $a, FeedEntry $b): int => $a->id <=> $b->id);

        return $entries;
    }

    #[\Override]
    public function settle(FeedEntry $entry): bool
    {
        $deleted = $this->database->execute(
            'DELETE FROM fga_outbox WHERE id = :id AND generation = :generation',
            ['id' => $entry->id, 'generation' => $entry->generation],
        );
        if ($deleted === 1) {
            return true;
        }
        $this->database->execute('UPDATE fga_outbox SET claimed_until = NULL WHERE id = :id', ['id' => $entry->id]);

        return false;
    }

    #[\Override]
    public function postpone(FeedEntry $entry, DateTimeImmutable $next): void
    {
        $this->database->execute(
            <<<'SQL'
                UPDATE fga_outbox SET attempts = attempts + 1, next_attempt_at = :next, claimed_until = NULL
                WHERE id = :id
                SQL,
            ['id' => $entry->id, 'next' => Timestamp::toDatabase($next)],
        );
    }

    #[\Override]
    public function pending(): int
    {
        /** @var int|string $count */
        $count = $this->database->fetchValue('SELECT count(*) FROM fga_outbox');

        return max(0, (int) $count);
    }

    /** @param EntryRow $row */
    private static function hydrate(array $row): FeedEntry
    {
        return new FeedEntry(
            max(1, (int) $row['id']),
            ResourceServerId::fromString($row['resource_server_id']),
            FeedSubject::fromString($row['subject']),
            max(1, (int) $row['generation']),
            max(0, (int) $row['attempts']),
        );
    }
}
