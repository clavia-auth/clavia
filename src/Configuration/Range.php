<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Configuration;

use Attribute;

/**
 * Inclusive bounds of an integer setting, checked when {@see Settings} is built.
 */
#[Attribute(Attribute::TARGET_PARAMETER)]
final readonly class Range
{
    public function __construct(
        public ?int $min = null,
        public ?int $max = null,
    ) {
    }
}
