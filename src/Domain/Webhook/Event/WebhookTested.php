<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Webhook\Event;

use Clavia\Domain\Shared\DomainEvent;
use Clavia\Domain\Webhook\WebhookEndpointId;

/** An operator asked for a test delivery to the endpoint. */
final readonly class WebhookTested implements DomainEvent
{
    public function __construct(public WebhookEndpointId $id)
    {
    }
}
