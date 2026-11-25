<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Provisioning\Event;

use Clavia\Domain\Provisioning\ProvisioningToken;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A provisioning token was revoked: it reaches `/scim/v2` no more, and the accounts it provisioned stay.
 */
final readonly class ProvisioningTokenRevoked implements DomainEvent
{
    public function __construct(
        public ProvisioningToken $token,
    ) {
    }
}
