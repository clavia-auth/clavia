<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Oidc;

/**
 * Where a signing key is in its life.
 *
 * There is no "pending" state: a key is created active (the first one, or by a
 * rotation) and only ever goes one way.
 */
enum SigningKeyStatus: string
{
    /** Signs every new token. At most one key is active at a time. */
    case Active = 'active';

    /** Signs nothing; stays published until every token it signed has expired. */
    case Retired = 'retired';
}
