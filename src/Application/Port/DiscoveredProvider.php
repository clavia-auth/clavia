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
 * Where an OpenID provider's discovery document says its endpoints are — each checked as
 * a URL this server may fetch.
 */
final readonly class DiscoveredProvider
{
    public function __construct(
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
    ) {
    }
}
