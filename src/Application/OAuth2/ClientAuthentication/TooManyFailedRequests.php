<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\ClientAuthentication;

use RuntimeException;

/**
 * Too many requests from this address, or by this client, failed recently: the endpoint
 * refuses before looking at the request (RFC 6585 §4, `429 Too Many Requests`).
 */
final class TooManyFailedRequests extends RuntimeException
{
    /**
     * @param positive-int $retryAfter Seconds after which a request may succeed again — the whole
     *                                 window, since every failure restarts it.
     */
    public function __construct(public readonly int $retryAfter)
    {
        parent::__construct('Too many failed requests.');
    }
}
