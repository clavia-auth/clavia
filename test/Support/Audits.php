<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Application\Audit\Audit;
use Clavia\Application\Audit\AuditContext;
use Clavia\Domain\Shared\Clock;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAuditLog;
use ClaviaTest\Support\Fake\SeededRandomSource;

/**
 * The audit recorder for unit tests, writing to an in-memory log the test can look at —
 * what the audit trails (`Application\Audit\Trail\*`) are built with.
 */
final class Audits
{
    private function __construct()
    {
    }

    /**
     * A recorder writing to `$log`, with the time taken from `$clock` — pass the use
     * case's own clock so that events carry the times the test controls.
     */
    public static function into(
        InMemoryAuditLog $log,
        ?Clock $clock = null,
        AuditContext $context = new AuditContext(),
    ): Audit {
        return new Audit($log, $context, $clock ?? new FrozenClock(), new SeededRandomSource());
    }
}
