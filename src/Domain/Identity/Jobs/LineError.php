<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity\Jobs;

/**
 * A line an import refused, in its report: its number (from 1) and why, never what it held, so a
 * report repeats no address and no hash.
 */
final readonly class LineError
{
    /**
     * @param positive-int     $line
     * @param non-empty-string $error  A stable code: `invalid_json`, `invalid_field`, `already_exists`…
     * @param non-empty-string $detail What is wrong, naming the field at fault.
     */
    public function __construct(
        public int $line,
        public string $error,
        public string $detail,
    ) {
    }
}
