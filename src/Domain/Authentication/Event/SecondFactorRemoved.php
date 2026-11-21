<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Event;

use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * Two-factor authentication was turned off for an account — by its holder, or reset
 * by an operator for somebody who lost both their phone and their recovery codes.
 */
final readonly class SecondFactorRemoved implements DomainEvent
{
    /**
     * @param bool $byTheirOwner False when an operator reset it.
     */
    public function __construct(
        public UserId $userId,
        public bool $byTheirOwner,
    ) {
    }
}
