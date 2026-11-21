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
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * Sessions stopped being valid before their time — by a sign-out, an application's
 * logout request or an operator. A session that runs out, or is replaced when the same
 * browser signs in again, is not reported.
 */
final readonly class SessionsEnded implements DomainEvent
{
    /**
     * @param list<Session> $sessions The sessions ended, possibly none.
     * @param ClientId|null $via      The application whose logout request ended them, if any.
     */
    public function __construct(
        public SessionEndReason $reason,
        public array $sessions,
        public ?ClientId $via = null,
    ) {
    }
}
