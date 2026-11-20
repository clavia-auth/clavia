<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Shared;

/**
 * The only source of randomness for the domain and the application layer.
 *
 * Every secret this server mints — codes, tokens, session identifiers, client secrets —
 * is drawn from here. The production adapter is the operating system's CSPRNG; nothing
 * weaker may ever implement this for anything but tests.
 */
interface RandomSource
{
    /**
     * @param positive-int $length
     *
     * @return non-empty-string Exactly `$length` uniformly random bytes.
     */
    public function bytes(int $length): string;

    /**
     * A uniformly random integer in `[$min, $max]`, both inclusive, with no modulo bias.
     */
    public function integer(int $min, int $max): int;
}
