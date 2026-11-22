<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

/**
 * The link was mailed.
 */
final readonly class PasswordLinkSent
{
    /**
     * @param bool $invitation True for an account with no password yet, false for a reset.
     */
    public function __construct(public bool $invitation)
    {
    }
}
