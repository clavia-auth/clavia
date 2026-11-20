<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\System;

use Clavia\Domain\Shared\RandomSource;

/**
 * The operating system's cryptographically secure generator.
 *
 * `random_bytes()` and `random_int()` read the kernel CSPRNG and throw rather than
 * fall back to anything weaker.
 */
final readonly class SystemRandomSource implements RandomSource
{
    #[\Override]
    public function bytes(int $length): string
    {
        return random_bytes($length);
    }

    #[\Override]
    public function integer(int $min, int $max): int
    {
        return random_int($min, $max);
    }
}
