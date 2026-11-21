<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Consent\Event;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A person's consents to an application were withdrawn: it asks again next time.
 */
final readonly class ConsentWithdrawn implements DomainEvent
{
    public function __construct(
        public UserId $userId,
        public ClientId $clientId,
    ) {
    }
}
