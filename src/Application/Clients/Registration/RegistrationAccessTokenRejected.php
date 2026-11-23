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
 * No registration access token answering for this client: missing, unknown, rotated, or another
 * client's — one answer, `401 invalid_token` (RFC 7592 §2.1), so the caller learns nothing about
 * which clients exist or registered themselves.
 */
final class RegistrationAccessTokenRejected extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('The registration access token is invalid for this client.');
    }
}
