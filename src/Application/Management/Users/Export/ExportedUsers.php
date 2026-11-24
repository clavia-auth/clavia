<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users\Export;

/** What an export wrote: NDJSON, and how many accounts. */
final readonly class ExportedUsers
{
    /** @param int<0, max> $count */
    public function __construct(
        public string $content,
        public int $count,
    ) {
    }
}
