<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Psr\Http\Message\ServerRequestInterface;

/**
 * The address a request came from, for throttling: what the web server reports. Behind
 * Caddy over FastCGI that is the client's own; no forwarded header is consulted.
 */
final class ClientAddress
{
    private function __construct()
    {
    }

    public static function of(ServerRequestInterface $request): string
    {
        /** @var mixed $address */
        $address = $request->getServerParams()['REMOTE_ADDR'] ?? null;

        return is_string($address) && $address !== '' ? $address : 'unknown';
    }
}
