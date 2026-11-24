<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity\Event;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\Jobs\UserJobId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * The accounts of a connection were written out by an export job: a copy of the directory left the
 * server, which the trail records, by whom it was asked, how many, never which.
 */
final readonly class UsersExported implements DomainEvent
{
    /** @param int<0, max> $count */
    public function __construct(
        public UserJobId $job,
        public ConnectionName $connection,
        public int $count,
    ) {
    }
}
