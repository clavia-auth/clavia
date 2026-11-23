<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client\Event;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\Registration\InitialAccessTokenId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * An application was registered: by an operator, or by itself (RFC 7591) with the initial access
 * token `$registeredWith`.
 */
final readonly class ClientRegistered implements DomainEvent
{
    public function __construct(
        public Client $client,
        public ?InitialAccessTokenId $registeredWith = null,
    ) {
    }
}
