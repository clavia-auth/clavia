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
 * A provider as the login page offers it: the name for the link, the label to show.
 */
final readonly class ExternalProviderOption
{
    public function __construct(
        public string $name,
        public string $label,
    ) {
    }
}
