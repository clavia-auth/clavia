<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Webhooks;

/** What one run of `webhooks:deliver` did. */
final readonly class WebhooksDelivered
{
    public function __construct(
        public int $succeeded,
        public int $failed,
        public int $abandoned,
        public int $purged,
        public int $disabled = 0,
    ) {
    }
}
