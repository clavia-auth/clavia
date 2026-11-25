<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection\Saml\Event;

use Clavia\Domain\Connection\Saml\ServiceProviderKey;
use Clavia\Domain\Shared\DomainEvent;

/** The first pair of service provider keys was made. */
final readonly class ServiceProviderKeysGenerated implements DomainEvent
{
    public function __construct(public ServiceProviderKey $signing, public ServiceProviderKey $encryption)
    {
    }
}
