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

/**
 * One entry of the identity feed, as a worker claimed it: what to bring into step, in which API's
 * store, and how many times sending it has failed.
 *
 * `generation` grows each time the same subject is queued again for the same API. A worker that
 * sent generation 3 settles the entry only if it is still at 3: a change committed while it was
 * sending leaves the entry for another pass, which reads Clavia again.
 */
final readonly class FeedEntry
{
    /**
     * @param positive-int $id
     * @param positive-int $generation
     * @param non-negative-int $attempts Failed sends so far.
     */
    public function __construct(
        public int $id,
        public ResourceServerId $resourceServerId,
        public FeedSubject $subject,
        public int $generation,
        public int $attempts,
    ) {
    }

    /**
     * Seconds to wait after one more failure (§5.4): 5 s, a minute, five minutes, then every ten
     * minutes. An entry is never given up: dropping one could leave a person a role they lost.
     *
     * @return positive-int
     */
    public function retryDelay(): int
    {
        return [5, 60, 300][$this->attempts] ?? 600;
    }
}
