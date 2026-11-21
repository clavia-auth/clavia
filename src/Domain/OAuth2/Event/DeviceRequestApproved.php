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
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\DomainEvent;
use Clavia\Domain\Shared\ScopeSet;

/**
 * A person approved a device's request (RFC 8628) on the device page.
 */
final readonly class DeviceRequestApproved implements DomainEvent
{
    public function __construct(
        public UserId $userId,
        public ClientId $clientId,
        public ScopeSet $scope,
        public ?Audience $audience,
    ) {
    }
}
