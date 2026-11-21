<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Shared;

/**
 * Something that happened, said in the domain's words: an application registered, a
 * sign-in refused, a refresh token replayed.
 *
 * An event is a fact in the past tense, immutable, carrying the domain objects it is
 * about and never a secret — what an application was handed in the clear (a code, a
 * token, a password) is not part of what happened to it. Events are dispatched by the
 * use case that made the change, inside its transaction, through the application's
 * `DomainEvents` port; what follows from them (the audit trail, back-channel logout) is
 * decided by whoever subscribes, not by the code that dispatches.
 *
 * An event carries no time: it is handled as it is dispatched, and whoever records it
 * reads the clock.
 */
interface DomainEvent
{
}
