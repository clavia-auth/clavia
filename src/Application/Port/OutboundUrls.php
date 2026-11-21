<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

/**
 * Whether this server may send requests of its own to a URL an operator gave it: https,
 * and not at this server or its internal network (no loopback, private, link-local or
 * cloud-metadata address).
 *
 * Asked when the URL is registered, so the operator hears about it then; the adapter that
 * sends asks again at every request, because what a name resolves to can change.
 */
interface OutboundUrls
{
    /**
     * @param string $what What the URL is, for the reason: "back-channel logout URI".
     *
     * @return string|null Why the URL is refused; null when it may be used.
     */
    public function refusal(string $url, string $what): ?string;
}
