<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Shared\DomainEvent;

/**
 * Where a use case says what happened.
 *
 * Dispatch is synchronous: every subscriber has handled the event when `dispatch()`
 * returns, in the caller's transaction if it has one — so an audit event commits and
 * rolls back with the change it describes. A subscriber that fails fails the use case;
 * nothing is swallowed. Work that must not hold the request up (a call to another
 * server) is the subscriber's to defer, through `DeferredTasks`.
 */
interface DomainEvents
{
    public function dispatch(DomainEvent $event): void;
}
