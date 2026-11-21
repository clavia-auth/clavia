<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client\Event;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * An application's registration changed.
 */
final readonly class ClientChanged implements DomainEvent
{
    /**
     * @param list<string> $changed What changed, by name — never to what.
     */
    public function __construct(
        public ClientId $clientId,
        public array $changed,
    ) {
    }
}
