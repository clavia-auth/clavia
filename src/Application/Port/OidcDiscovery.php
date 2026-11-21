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
 * OpenID Provider Configuration (OIDC Discovery 1.0 §4), fetched when an operator
 * registers a provider or changes its issuer — at the keyboard, where a wrong URL can be
 * corrected, rather than at a user's sign-in.
 */
interface OidcDiscovery
{
    /**
     * The endpoints the issuer's own document names, once it is established that the
     * document is the issuer's — its `issuer` equals the one asked for — and that this
     * server may fetch every URL involved.
     *
     * @throws DiscoveryFailed
     */
    public function discover(string $issuer): DiscoveredProvider;
}
