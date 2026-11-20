<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Shared;

use DateTimeImmutable;

/**
 * The only source of "now" for the domain and the application layer.
 *
 * Expiry is most of what an authorization server decides — codes, tokens, sessions,
 * challenges — so time is an input like any other, never read from the system inside
 * a rule. Tests freeze it and move it forward.
 */
interface Clock
{
    /** The current instant, in UTC. */
    public function now(): DateTimeImmutable;
}
