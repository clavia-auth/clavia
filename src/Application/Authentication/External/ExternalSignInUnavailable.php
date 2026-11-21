<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External;

/**
 * The connection exists and works, but the application the sign-in is for does not let
 * its users in through it: refused, not merely hidden from the login page.
 */
final readonly class ExternalSignInUnavailable
{
    /**
     * @param string $providerLabel The connection's display name.
     */
    public function __construct(public string $providerLabel)
    {
    }
}
