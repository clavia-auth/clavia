<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Webhook;

/** Where a delivery stands. */
enum WebhookDeliveryStatus: string
{
    /** Waiting for its next attempt. */
    case Pending = 'pending';

    /** A 2xx came back. */
    case Succeeded = 'succeeded';

    /** Given up on: the retries ran out, or it can no longer be sent (endpoint off, event purged). */
    case Abandoned = 'abandoned';
}
