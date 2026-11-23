<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

use RuntimeException;

/**
 * No usable initial access token: missing, unknown, expired, revoked or used up — one answer,
 * `401 invalid_token` (RFC 7591 §3, RFC 6750 §3.1), so the caller learns nothing about which exist.
 */
final class InitialAccessTokenRejected extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('The initial access token is invalid, expired, revoked or used up.');
    }
}
