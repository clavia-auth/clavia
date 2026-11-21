<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\ResourceServer\Event;

use Clavia\Domain\ResourceServer\ClientGrant;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A machine client was granted access to an API, as itself.
 */
final readonly class ClientAccessGranted implements DomainEvent
{
    /**
     * @param Audience $audience The API, by identifier.
     */
    public function __construct(
        public ClientGrant $grant,
        public Audience $audience,
    ) {
    }
}
