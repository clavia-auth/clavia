<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Authorization\FeedEntry;
use Clavia\Domain\Authorization\FeedSubject;
use Clavia\Domain\Authorization\IdentityFeedOutbox;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use DateTimeImmutable;

/**
 * The identity feed's outbox in memory, held to {@see \ClaviaTest\Support\Contract\IdentityFeedOutboxContract}.
 *
 * @psalm-type Row = array{id: positive-int, api: ResourceServerId, subject: FeedSubject,
 *     generation: positive-int, attempts: non-negative-int, due: DateTimeImmutable,
 *     claimedUntil: DateTimeImmutable|null}
 */
final class InMemoryIdentityFeedOutbox implements IdentityFeedOutbox
{
    /** @var array<string, Row> By API and subject. */
    private array $rows = [];

    /** @var positive-int */
    private int $next = 1;

    /** The APIs entries refer to, once a repository names itself (it does when built with this outbox). */
    private ?ResourceServerRepository $apis = null;

    /** Hold entries to the APIs of `$apis`, as the table's foreign key does. */
    public function referTo(ResourceServerRepository $apis): void
    {
        $this->apis = $apis;
    }

    #[\Override]
    public function enqueue(ResourceServerId $api, array $subjects, DateTimeImmutable $now): void
    {
        // The foreign key on `resource_servers`: an API gone queues nothing.
        if ($this->apis !== null && $this->apis->find($api) === null) {
            return;
        }
        foreach ($subjects as $subject) {
            $key = $api->value . ' ' . $subject->toString();
            $row = $this->rows[$key] ?? null;
            if ($row === null) {
                $this->rows[$key] = [
                    'id' => $this->next++,
                    'api' => $api,
                    'subject' => $subject,
                    'generation' => 1,
                    'attempts' => 0,
                    'due' => $now,
                    'claimedUntil' => null,
                ];
                continue;
            }
            $row['generation']++;
            $row['due'] = min($row['due'], $now);
            $this->rows[$key] = $row;
        }
    }

    #[\Override]
    public function claim(DateTimeImmutable $now, DateTimeImmutable $until, int $limit): array
    {
        $free = array_filter(
            $this->rows,
            static fn (array $row): bool => $row['due'] <= $now
                && ($row['claimedUntil'] === null || $row['claimedUntil'] < $now),
        );
        uasort($free, static fn (array $a, array $b): int => [$a['due'], $a['id']] <=> [$b['due'], $b['id']]);

        $claimed = [];
        foreach (array_slice($free, 0, $limit, true) as $key => $row) {
            $this->rows[$key]['claimedUntil'] = $until;
            $claimed[] = new FeedEntry($row['id'], $row['api'], $row['subject'], $row['generation'], $row['attempts']);
        }
        usort($claimed, static fn (FeedEntry $a, FeedEntry $b): int => $a->id <=> $b->id);

        return $claimed;
    }

    #[\Override]
    public function settle(FeedEntry $entry): bool
    {
        $key = $this->keyOf($entry);
        if ($key === null) {
            return false;
        }
        if ($this->rows[$key]['generation'] === $entry->generation) {
            unset($this->rows[$key]);

            return true;
        }
        $this->rows[$key]['claimedUntil'] = null;

        return false;
    }

    #[\Override]
    public function postpone(FeedEntry $entry, DateTimeImmutable $next): void
    {
        $key = $this->keyOf($entry);
        if ($key === null) {
            return;
        }
        $this->rows[$key]['attempts']++;
        $this->rows[$key]['due'] = $next;
        $this->rows[$key]['claimedUntil'] = null;
    }

    #[\Override]
    public function pending(): int
    {
        return count($this->rows);
    }

    /** The cascade from `resource_servers`: an API deleted takes its entries along. */
    public function forgetApi(ResourceServerId $api): void
    {
        $this->rows = array_filter($this->rows, static fn (array $row): bool => ! $row['api']->equals($api));
    }

    /**
     * What waits, for a test: `<api id> <subject>` each, sorted.
     *
     * @return list<string>
     */
    public function waiting(): array
    {
        $keys = array_keys($this->rows);
        sort($keys);

        return $keys;
    }

    private function keyOf(FeedEntry $entry): ?string
    {
        foreach ($this->rows as $key => $row) {
            if ($row['id'] === $entry->id) {
                return $key;
            }
        }

        return null;
    }
}
