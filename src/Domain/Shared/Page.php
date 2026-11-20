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
 * One page of a collection, with the total, so that a caller can tell the last page
 * from one that happens to be empty.
 *
 * @template T
 */
final readonly class Page
{
    /**
     * @param list<T>          $items
     * @param non-negative-int $total Matching items across every page.
     */
    public function __construct(
        public array $items,
        public int $total,
        public PageRequest $request,
    ) {
    }

    /**
     * The same page with every item transformed.
     *
     * @template U
     * @param callable(T): U $transform
     * @return self<U>
     */
    public function map(callable $transform): self
    {
        return new self(array_map($transform, $this->items), $this->total, $this->request);
    }
}
