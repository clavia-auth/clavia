<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client\Event;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * The connections an application signs people in through were replaced.
 */
final readonly class ClientConnectionsChanged implements DomainEvent
{
    /**
     * @param list<ConnectionName> $connections The connections it enables now.
     */
    public function __construct(
        public ClientId $clientId,
        public array $connections,
    ) {
    }
}
