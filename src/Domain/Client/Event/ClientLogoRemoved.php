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
 * An application's logo was removed: the pages show this server's again.
 */
final readonly class ClientLogoRemoved implements DomainEvent
{
    public function __construct(public ClientId $clientId)
    {
    }
}
