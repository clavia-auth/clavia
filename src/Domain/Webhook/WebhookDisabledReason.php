<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Webhook;

/** Why an endpoint is switched off. */
enum WebhookDisabledReason: string
{
    /** An operator switched it off. */
    case Operator = 'operator';

    /** Every delivery to it failed for {@see WebhookEndpoint::DEAD_AFTER_DAYS} days running. */
    case Failing = 'failing';
}
