<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authorization\Event;

use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * Fine-grained authorization was switched off for an API: its store kept, or deleted with every
 * relationship in it when the operator confirmed it.
 */
final readonly class AuthorizationDisabled implements DomainEvent
{
    public function __construct(
        public ResourceServerId $resourceServerId,
        public bool $storeDeleted,
    ) {
    }
}
