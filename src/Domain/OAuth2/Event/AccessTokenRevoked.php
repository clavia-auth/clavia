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
 * A client gave an access token back (RFC 7009).
 */
final readonly class AccessTokenRevoked implements DomainEvent
{
    /**
     * @param UserId|null $userId Null for a machine token.
     */
    public function __construct(
        public ClientId $clientId,
        public ?UserId $userId,
    ) {
    }
}
