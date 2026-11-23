<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Configuration;

/**
 * Who may register a client through the registration endpoint (`CLAVIA_CLIENT_REGISTRATION`,
 * RFC 7591; docs/design/dynamic-client-registration.md §3).
 */
enum ClientRegistration: string
{
    /** Nobody: there is no registration endpoint, and discovery names none. */
    case Off = 'off';

    /** A bearer of an initial access token an operator issued (RFC 7591 §3). */
    case Token = 'token';
}
