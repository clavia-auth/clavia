<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users\Jobs;

/**
 * What one `clavia jobs:run` did.
 */
final readonly class JobsRun
{
    /**
     * @param non-negative-int $completed Jobs run to their end.
     * @param non-negative-int $stalled   Jobs found running with no worker left, now failed.
     * @param non-negative-int $purged    Finished jobs deleted, past their retention.
     */
    public function __construct(
        public int $completed,
        public int $stalled,
        public int $purged,
    ) {
    }
}
