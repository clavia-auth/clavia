<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client;

/**
 * The grants this server offers at the token endpoint. A client is registered for the
 * ones it may use; nothing is granted by default.
 */
enum GrantType: string
{
    /** RFC 6749 §4.1, always with PKCE (RFC 7636). */
    case AuthorizationCode = 'authorization_code';

    /**
     * RFC 6749 §4.4: a confidential client authenticating as itself. The token it gets
     * has no subject.
     */
    case ClientCredentials = 'client_credentials';

    /**
     * RFC 6749 §6: a refresh token, issued alongside the code flow's tokens, exchanged for
     * a new pair. Rotated on every use; a replay revokes the family.
     */
    case RefreshToken = 'refresh_token';
}
