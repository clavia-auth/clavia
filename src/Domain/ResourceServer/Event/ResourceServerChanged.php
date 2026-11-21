<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\ResourceServer\Event;

use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * An API's definition changed.
 */
final readonly class ResourceServerChanged implements DomainEvent
{
    /**
     * @param list<string> $changed What changed, by name — never to what.
     */
    public function __construct(
        public ResourceServerId $resourceServerId,
        public array $changed,
    ) {
    }
}
