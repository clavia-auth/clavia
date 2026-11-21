<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Event;

use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A browser became authenticated: a session was established, by whichever first and
 * second factors it took.
 */
final readonly class SignedIn implements DomainEvent
{
    /**
     * @param Session $session The new session.
     */
    public function __construct(
        public Session $session,
    ) {
    }
}
