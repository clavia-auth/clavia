<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Event;

use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A signed-in person gave one more factor, and their session was raised in place to meet
 * what a request asked for (docs/design/mfa-policies.md §5.2).
 */
final readonly class SessionSteppedUp implements DomainEvent
{
    /**
     * @param Session                    $session The session as raised.
     * @param list<AuthenticationMethod> $added   What the new factor added to `amr`.
     */
    public function __construct(
        public Session $session,
        public array $added,
    ) {
    }
}
