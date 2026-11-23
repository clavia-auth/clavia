<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Audit;

/** What kind of thing an audit event was about. */
enum TargetType: string
{
    case User = 'user';
    case Client = 'client';
    case ResourceServer = 'resource_server';
    case Role = 'role';
    case Connection = 'connection';
    case SigningKey = 'signing_key';
    case InitialAccessToken = 'initial_access_token';
}
