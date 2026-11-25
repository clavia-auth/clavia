<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

use Clavia\Domain\Connection\ConnectionName;

/**
 * A `SAMLResponse` as the identity provider POSTed it, kept for the minute between the cross-site
 * POST, which carries no `SameSite=Lax` cookie, and the GET it is turned into, which does
 * (docs/design/saml-connections.md §2, "The browser binding").
 */
final readonly class ParkedSamlResponse
{
    public function __construct(
        public ConnectionName $connection,
        #[\SensitiveParameter] public string $response,
        #[\SensitiveParameter] public string $relayState,
    ) {
    }
}
