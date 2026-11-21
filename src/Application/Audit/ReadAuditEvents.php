<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Audit;

use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Audit\AuditQuery;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/** The audit trail, newest first, filtered as asked. */
final readonly class ReadAuditEvents
{
    public function __construct(private AuditLog $log)
    {
    }

    /**
     * @return Page<AuditEvent>
     */
    public function __invoke(AuditQuery $query, PageRequest $request): Page
    {
        return $this->log->page($query, $request);
    }
}
