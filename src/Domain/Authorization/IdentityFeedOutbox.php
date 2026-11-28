<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authorization;

use Clavia\Domain\ResourceServer\ResourceServerId;
use DateTimeImmutable;

/**
 * The identity feed's outbox (docs/design/fine-grained-authorization.md §5.4): what Clavia still has
 * to bring into step in the decision engine, written in the transaction of the change, so a committed
 * change is never lost and a rolled-back one sends nothing.
 *
 * One entry per API and subject: queuing a subject already waiting makes it due now and moves its
 * generation on, so a burst of changes to one person is one send. An entry goes with its API.
 */
interface IdentityFeedOutbox
{
    /**
     * Queue each subject for the API, due now.
     *
     * @param list<FeedSubject> $subjects
     */
    public function enqueue(ResourceServerId $api, array $subjects, DateTimeImmutable $now): void;

    /**
     * Claim up to `$limit` entries that are due and that no worker holds, oldest first, until
     * `$until`. A worker that dies leaves its claim to lapse.
     *
     * @param positive-int $limit
     *
     * @return list<FeedEntry>
     */
    public function claim(DateTimeImmutable $now, DateTimeImmutable $until, int $limit): array;

    /**
     * The entry was sent: gone, unless it was queued again since it was claimed, in which case it is
     * released, due as it was queued.
     *
     * @return bool Whether it is gone.
     */
    public function settle(FeedEntry $entry): bool;

    /** Sending failed: one more attempt counted, released, due at `$next`. */
    public function postpone(FeedEntry $entry, DateTimeImmutable $next): void;

    /**
     * How many entries wait, due or not.
     *
     * @return non-negative-int
     */
    public function pending(): int;
}
