<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Webhook;

/**
 * Why an attempt failed, the only thing kept of a receiver's answer besides its status code: never
 * its body or headers (docs/design/webhooks.md §2).
 */
enum DeliveryFailure: string
{
    /** It answered, with something other than a 2xx (a 3xx too: redirects are not followed). */
    case Status = 'status';

    /** It could not be reached in time: refused, reset, timed out. */
    case Connection = 'connection';

    /** `OutboundUrlPolicy` refuses its URL now (it resolves somewhere private). */
    case RefusedUrl = 'refused_url';

    /** The endpoint is switched off: nothing is sent, the delivery is abandoned. */
    case Disabled = 'disabled';

    /** The audit event was purged before it could be sent. */
    case EventPurged = 'event_purged';
}
