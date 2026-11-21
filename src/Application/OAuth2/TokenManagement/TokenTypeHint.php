<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\TokenManagement;

/**
 * The kinds of token introspection and revocation can be asked about (RFC 7662 §2.1,
 * RFC 7009 §2.1). An authorization code is not one: it is redeemed, never presented.
 */
enum TokenTypeHint: string
{
    case AccessToken = 'access_token';

    case RefreshToken = 'refresh_token';
}
