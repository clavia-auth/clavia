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
 * A provisioning token was issued: a directory holding it may now provision its connection's accounts.
 */
final readonly class ProvisioningTokenIssued implements DomainEvent
{
    public function __construct(
        public ProvisioningToken $token,
    ) {
    }
}
