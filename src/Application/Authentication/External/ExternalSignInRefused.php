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
 * An external sign-in that ended without a session or a challenge.
 */
final readonly class ExternalSignInRefused
{
    /**
     * @param string $providerLabel The provider's own name, for the message ("… with Google").
     */
    public function __construct(
        public ExternalSignInFailure $reason,
        public string $providerLabel,
    ) {
    }
}
