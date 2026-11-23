<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\ProtectedResource;

/**
 * How an access token was presented to a protected resource: as a bearer token (RFC 6750 §2.1),
 * or as a DPoP-bound one with a proof (RFC 9449 §7.1). A refusal is challenged in the same scheme.
 */
enum TokenScheme: string
{
    case Bearer = 'Bearer';
    case Dpop = 'DPoP';
}
