<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Event;

use Clavia\Domain\Shared\DomainEvent;
use Closure;

/**
 * Something that acts on domain events: the audit trail, back-channel logout.
 *
 * A subscriber lists the events it handles, each with the closure that handles it — a
 * first-class callable on one of its own methods, typed with the event it takes. The
 * composition root registers every subscriber (`ConfigProvider::EVENT_SUBSCRIBERS`); a
 * subscriber never registers itself, and the code dispatching an event never knows who
 * listens.
 */
interface EventSubscriber
{
    /**
     * @return array<class-string<DomainEvent>, Closure> Each closure takes an instance of its key.
     */
    public function subscriptions(): array;
}
