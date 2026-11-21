<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Domain\Audit\AuditLog;
use ClaviaTest\Support\Contract\AuditLogContract;
use ClaviaTest\Support\Fake\InMemoryAuditLog;
use PHPUnit\Framework\TestCase;

final class InMemoryAuditLogTest extends TestCase
{
    use AuditLogContract;

    private InMemoryAuditLog $log;

    #[\Override]
    protected function setUp(): void
    {
        $this->log = new InMemoryAuditLog();
    }

    #[\Override]
    protected function auditLog(): AuditLog
    {
        return $this->log;
    }
}
