<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Audit;

use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Shared\Clock;

/**
 * Trims the audit trail to its retention (`CLAVIA_AUDIT_RETENTION_DAYS`): what is older is
 * removed for good. Run from a scheduler (`clavia audit:purge`); nothing else ever deletes
 * an event.
 */
final readonly class PurgeAuditEvents
{
    /**
     * @param positive-int $retentionDays
     */
    public function __construct(
        private AuditLog $log,
        private Clock $clock,
        private int $retentionDays,
    ) {
    }

    /**
     * @return non-negative-int The events removed.
     */
    public function __invoke(): int
    {
        return $this->log->purgeBefore($this->clock->now()->modify(sprintf('-%d days', $this->retentionDays)));
    }
}
