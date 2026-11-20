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
 * How a client proves itself at the token endpoint (RFC 6749 §2.3, RFC 7591 §2).
 *
 * A client has exactly one: a registration that accepted several would let an attacker
 * holding a client id pick the weakest.
 */
enum ClientAuthMethod: string
{
    /** No authentication: a public client names itself with `client_id` and nothing else. */
    case None = 'none';

    /** HTTP Basic (RFC 6749 §2.3.1) — the method every server must support. */
    case ClientSecretBasic = 'client_secret_basic';

    /** `client_id` and `client_secret` in the request body. */
    case ClientSecretPost = 'client_secret_post';

    public function usesASecret(): bool
    {
        return $this !== self::None;
    }
}
