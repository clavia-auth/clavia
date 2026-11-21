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

    /**
     * RFC 8628: a device with no browser asks for a code, a person approves it on another
     * screen, and the device polls for its tokens.
     */
    case DeviceCode = 'urn:ietf:params:oauth:grant-type:device_code';

    /** Whether this grant issues tokens on a person's behalf, which a refresh token can renew. */
    public function actsForAPerson(): bool
    {
        return $this === self::AuthorizationCode || $this === self::DeviceCode;
    }
}
