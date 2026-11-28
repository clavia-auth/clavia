<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Authorization\Tuple;

/**
 * One page of relationships read from the decision engine, and the token that reads the next.
 */
final readonly class TuplePage
{
    /**
     * @param list<Tuple> $tuples
     * @param string $next The engine's own continuation token, opaque; '' when this page is the last.
     */
    public function __construct(
        public array $tuples,
        public string $next,
    ) {
    }
}
