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
 * What a refresh token presented at the token endpoint turned out to be.
 */
enum Refresh
{
    /** Live, and the client's own: it may be spent. */
    case Usable;

    /**
     * Issued to another client. Nothing changes: client ids are public, so a thief would
     * present the right one — this is a misconfigured client, not a leak.
     */
    case IssuedToAnotherClient;

    /** Revoked, with its whole family. */
    case Revoked;

    /**
     * Already spent: two parties hold the chain, and there is no telling which one is
     * asking. The family must be revoked (RFC 6749 §10.4).
     */
    case Replayed;

    /** Past its idle limit or its family's deadline. Not spent: `used` means refreshed. */
    case Expired;
}
