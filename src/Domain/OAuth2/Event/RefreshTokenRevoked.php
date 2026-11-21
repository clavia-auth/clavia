<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2\Event;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A client gave a refresh token back (RFC 7009): its family and their access tokens
 * went with it.
 */
final readonly class RefreshTokenRevoked implements DomainEvent
{
    public function __construct(
        public ClientId $clientId,
        public UserId $userId,
    ) {
    }
}
