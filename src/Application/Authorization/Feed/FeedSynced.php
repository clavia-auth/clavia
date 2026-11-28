<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Feed;

/**
 * What a run of the identity feed did: entries sent, entries the engine could not take (retried
 * later), and what is left waiting.
 */
final readonly class FeedSynced
{
    /**
     * @param non-negative-int $sent
     * @param non-negative-int $failed
     * @param non-negative-int $pending
     * @param bool $available Whether fine-grained authorization is on: off, nothing was sent.
     */
    public function __construct(
        public int $sent,
        public int $failed,
        public int $pending,
        public bool $available,
    ) {
    }
}
