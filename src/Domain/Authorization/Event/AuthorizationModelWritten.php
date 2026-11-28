<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authorization\Event;

use Clavia\Domain\Authorization\AuthorizationModelId;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A new version of an API's authorization model is in force. Named by its id, never by its content:
 * the model is configuration an operator reads where it is kept.
 */
final readonly class AuthorizationModelWritten implements DomainEvent
{
    public function __construct(
        public ResourceServerId $resourceServerId,
        public AuthorizationModelId $model,
    ) {
    }
}
