<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Feed;

/**
 * What bringing a store into step changed there: relationships written and deleted, counted.
 */
final readonly class Reconciled
{
    /**
     * @param non-negative-int $written
     * @param non-negative-int $deleted
     */
    public function __construct(
        public int $written,
        public int $deleted,
    ) {
    }

    public static function nothing(): self
    {
        return new self(0, 0);
    }

    public function and(self $other): self
    {
        return new self($this->written + $other->written, $this->deleted + $other->deleted);
    }
}
