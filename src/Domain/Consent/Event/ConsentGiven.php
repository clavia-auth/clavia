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
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\DomainEvent;
use Clavia\Domain\Shared\ScopeSet;

/**
 * A person allowed an application the scopes it asked for; the consent on record
 * widens to cover them.
 */
final readonly class ConsentGiven implements DomainEvent
{
    /**
     * @param ResourceServerId|null $resourceServerId The API asked for, if any.
     * @param ScopeSet              $scope            What was asked.
     */
    public function __construct(
        public UserId $userId,
        public ClientId $clientId,
        public ?ResourceServerId $resourceServerId,
        public ScopeSet $scope,
    ) {
    }
}
