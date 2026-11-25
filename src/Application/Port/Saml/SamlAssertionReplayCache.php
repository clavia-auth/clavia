<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

use Clavia\Domain\Connection\ConnectionName;

/**
 * The assertion ids a connection has accepted, until they expire (SAML Profiles §4.1.4.5): the same
 * assertion, posted twice by the same browser, signs nobody in the second time.
 */
interface SamlAssertionReplayCache
{
    /**
     * Record the assertion, atomically: true the first time, false for a replay.
     *
     * @param positive-int $ttlSeconds
     */
    #[\NoDiscard]
    public function claimAssertion(ConnectionName $connection, string $assertionId, int $ttlSeconds): bool;
}
