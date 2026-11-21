<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Audit;

use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use DateTimeImmutable;

/**
 * The audit trail: appended to, read, and trimmed to its retention — never edited.
 */
interface AuditLog
{
    /**
     * Inside a transaction when the caller holds one: an action that is rolled back leaves
     * no event behind, and one that commits never lacks its event.
     */
    public function append(AuditEvent $event): void;

    /**
     * The events matching `$query`, newest first.
     *
     * @return Page<AuditEvent>
     */
    public function page(AuditQuery $query, PageRequest $request): Page;

    /**
     * Remove every event older than `$before`; the count removed.
     *
     * @return non-negative-int
     */
    public function purgeBefore(DateTimeImmutable $before): int;
}
