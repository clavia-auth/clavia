<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Shared\Url;

/**
 * Posts one webhook delivery: checks the URL against `OutboundUrlPolicy` again, connects to the
 * addresses it checked, follows no redirect, reads nothing of the answer but its status.
 */
interface WebhookSender
{
    /** @param array<string, string> $headers */
    public function send(Url $url, array $headers, string $body): SendOutcome;
}
