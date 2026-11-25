<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

/** The assertion consumer service's one-time handles (Redis, {@see TTL_SECONDS}). */
interface SamlResponseStore
{
    /** Long enough for one 303, short enough that a parked response does not linger. */
    public const int TTL_SECONDS = 60;

    public function park(#[\SensitiveParameter] string $handle, ParkedSamlResponse $response): void;

    /** The response, once: claimed and forgotten in one step. */
    public function claim(#[\SensitiveParameter] string $handle): ?ParkedSamlResponse;
}
