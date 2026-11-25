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
use Clavia\Domain\Webhook\WebhookEndpoint;

/** An endpoint was registered. Never carries a secret. */
final readonly class WebhookCreated implements DomainEvent
{
    public function __construct(public WebhookEndpoint $endpoint)
    {
    }
}
