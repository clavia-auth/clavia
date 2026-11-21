<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity\Event;

use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * An account changed.
 */
final readonly class UserChanged implements DomainEvent
{
    /**
     * @param list<string> $changed     What changed, by name — never to what.
     * @param bool         $deactivated Whether this change deactivated it.
     */
    public function __construct(
        public UserId $userId,
        public array $changed,
        public bool $deactivated,
    ) {
    }
}
