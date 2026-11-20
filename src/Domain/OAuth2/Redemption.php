<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

/**
 * What happened when a client tried to redeem an authorization code.
 */
enum Redemption
{
    /** The code was live and is now spent. */
    case Redeemed;

    /** The code belongs to another client. Nothing changed. */
    case IssuedToAnotherClient;

    /**
     * The code was already spent: it has leaked. Everything it produced must be revoked
     * (RFC 6749 §4.1.2).
     */
    case Replayed;

    /** The code outlived its lifetime. It is not spent: `used` means redeemed, not merely seen. */
    case Expired;
}
