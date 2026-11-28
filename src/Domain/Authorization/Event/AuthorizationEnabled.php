<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authorization\Event;

use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * Fine-grained authorization was switched on for an API, in the store named (a new one, or the one
 * kept since it was switched off).
 */
final readonly class AuthorizationEnabled implements DomainEvent
{
    public function __construct(
        public ResourceServerId $resourceServerId,
        public StoreId $store,
    ) {
    }
}
