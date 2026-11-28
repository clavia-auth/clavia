<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Feed;

use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\Authorization\FeedEntry;
use Clavia\Domain\Authorization\IdentityFeedOutbox;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;

/**
 * Sends what the identity feed's outbox holds (docs/design/fine-grained-authorization.md §5.4): after
 * the response that queued it, and every minute from `bin/clavia fga:sync`, which picks up what
 * failed. Each entry due is claimed, its subject brought into step, and the entry settled; an entry
 * the engine could not take waits 5 s, a minute, five minutes, then ten minutes at a time, and is
 * never given up.
 */
final readonly class SyncIdentityFeed
{
    /** The cron's run: a minute, less the time to start the next one. */
    public const int BUDGET_SECONDS = 50;

    /** A worker's hold on an entry: longer than one entry takes, short enough to lapse soon after a crash. */
    private const int CLAIM_SECONDS = 30;

    private const int ENTRIES_PER_CLAIM = 10;

    /**
     * @param bool $available Whether fine-grained authorization is on (`CLAVIA_FGA_URL`): off, the
     *                        outbox is left as it is.
     */
    public function __construct(
        private IdentityFeedOutbox $outbox,
        private ResourceServerRepository $resourceServers,
        private StoreReconciler $reconciler,
        private Clock $clock,
        private bool $available,
    ) {
    }

    /**
     * @param positive-int $budgetSeconds How long to keep claiming entries.
     */
    public function __invoke(int $budgetSeconds = self::BUDGET_SECONDS): FeedSynced
    {
        if (! $this->available) {
            return new FeedSynced(0, 0, $this->outbox->pending(), false);
        }
        $deadline = $this->clock->now()->modify(sprintf('+%d seconds', $budgetSeconds));
        $sent = 0;
        $failed = 0;

        while ($this->clock->now() < $deadline) {
            $now = $this->clock->now();
            $claimed = $this->outbox->claim(
                $now,
                $now->modify(sprintf('+%d seconds', self::CLAIM_SECONDS)),
                self::ENTRIES_PER_CLAIM,
            );
            if ($claimed === []) {
                break;
            }
            foreach ($claimed as $entry) {
                if ($this->send($entry)) {
                    ++$sent;
                } else {
                    ++$failed;
                }
            }
        }

        return new FeedSynced($sent, $failed, $this->outbox->pending(), true);
    }

    private function send(FeedEntry $entry): bool
    {
        $api = $this->resourceServers->find($entry->resourceServerId);
        try {
            if ($api !== null) {
                $this->reconciler->reconcile($api, $entry->subject);
            }
        } catch (DecisionEngineFailed) {
            // Logged by the adapter, by operation and reason; the entry waits its turn.
            $this->outbox->postpone(
                $entry,
                $this->clock->now()->modify(sprintf('+%d seconds', $entry->retryDelay())),
            );

            return false;
        }
        $this->outbox->settle($entry);

        return true;
    }
}
