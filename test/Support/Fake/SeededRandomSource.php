<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Shared\RandomSource;
use Random\Engine\Xoshiro256StarStar;
use Random\Randomizer;

/**
 * Reproducible "randomness": the same seed yields the same secrets, so a failing test
 * fails the same way twice. Never anything but a test double.
 */
final class SeededRandomSource implements RandomSource
{
    private Randomizer $randomizer;

    public function __construct(int $seed = 1)
    {
        $this->randomizer = new Randomizer(new Xoshiro256StarStar($seed));
    }

    #[\Override]
    public function bytes(int $length): string
    {
        return $this->randomizer->getBytes($length);
    }

    #[\Override]
    public function integer(int $min, int $max): int
    {
        return $this->randomizer->getInt($min, $max);
    }
}
