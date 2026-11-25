<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Webhooks;

use Clavia\Domain\Webhook\WebhookEndpoint;
use Clavia\Domain\Webhook\WebhookSecret;

/** An endpoint, with the only copy of its new secret the caller will ever be given. */
final readonly class WebhookWithSecret
{
    public function __construct(
        public WebhookEndpoint $endpoint,
        public WebhookSecret $secret,
    ) {
    }
}
