<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection\Event;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A connection changed.
 */
final readonly class ConnectionChanged implements DomainEvent
{
    /**
     * @param list<string> $changed What changed, by name — never to what.
     */
    public function __construct(
        public ConnectionName $name,
        public array $changed,
    ) {
    }
}
