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
 * A device's request was refused on the device page — by the person, or because they
 * hold nothing on the API it names.
 */
final readonly class DeviceRequestRefused implements DomainEvent
{
    /**
     * @param bool $holdsNothing True when the roles refused it rather than the person.
     */
    public function __construct(
        public UserId $userId,
        public ClientId $clientId,
        public ScopeSet $scope,
        public ?Audience $audience,
        public bool $holdsNothing,
    ) {
    }
}
