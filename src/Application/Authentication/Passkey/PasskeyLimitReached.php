<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

/**
 * The account already holds as many passkeys as it may (`CLAVIA_PASSKEY_MAX_PER_USER`).
 */
final readonly class PasskeyLimitReached
{
    /**
     * @param positive-int $limit
     */
    public function __construct(public int $limit)
    {
    }
}
