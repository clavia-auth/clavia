<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Event;

use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A passkey was removed from an account — by its holder, or by an operator for somebody who
 * lost the device it lived on.
 */
final readonly class PasskeyRemoved implements DomainEvent
{
    /**
     * @param bool $byTheirOwner False when an operator removed it.
     */
    public function __construct(
        public UserId $userId,
        public PasskeyId $passkeyId,
        public PasskeyName $name,
        public bool $byTheirOwner,
    ) {
    }
}
