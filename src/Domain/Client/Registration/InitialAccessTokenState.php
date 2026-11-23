<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client\Registration;

/**
 * Where an initial access token stands, as an operator sees it. Only `Active` registers a client.
 */
enum InitialAccessTokenState: string
{
    case Active = 'active';
    case Expired = 'expired';
    case UsedUp = 'used_up';
    case Revoked = 'revoked';
}
