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
 * Whether a client can keep a secret (RFC 6749 §2.1).
 */
enum ClientType: string
{
    /** Runs where its code can be read — a browser, a phone. PKCE is its only proof of possession. */
    case Public = 'public';

    /** Runs on a server and authenticates with a secret. */
    case Confidential = 'confidential';
}
