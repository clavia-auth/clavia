<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning\Groups;

use Clavia\Domain\Provisioning\ScimGroup;

/** One page of a `ListResponse` of groups (RFC 7644 §3.4.2). */
final readonly class ScimGroupPage
{
    /**
     * @param int<0, max>     $total
     * @param int<1, max>     $startIndex
     * @param list<ScimGroup> $groups
     */
    public function __construct(
        public int $total,
        public int $startIndex,
        public array $groups,
    ) {
    }
}
