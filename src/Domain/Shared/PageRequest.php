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
 * Which page of a collection to read, and what to look for in it.
 *
 * Paged rather than unbounded: asking for everything at once is asking the server to
 * build the whole list in memory, and a caller that needs every row can page for them.
 */
final readonly class PageRequest
{
    public const int MAX_PER_PAGE = 100;

    public const int MAX_SEARCH_LENGTH = 200;

    /**
     * @param positive-int $page    1-based.
     * @param positive-int $perPage
     * @param string       $search  A case-insensitive substring to look for, taken literally — `%`
     *                              and `_` are characters, not wildcards. Empty means no filter.
     */
    private function __construct(
        public int $page,
        public int $perPage,
        public string $search,
    ) {
    }

    /**
     * @throws InvalidValue When the page is below 1, the page size outside 1–100, or the search
     *                      longer than 200 characters.
     */
    public static function of(int $page = 1, int $perPage = 50, string $search = ''): self
    {
        if ($page < 1) {
            throw new InvalidValue('The page number starts at 1.');
        }
        if ($perPage < 1 || $perPage > self::MAX_PER_PAGE) {
            throw new InvalidValue(sprintf('A page holds 1 to %d items.', self::MAX_PER_PAGE));
        }
        $search = trim($search);
        if (mb_strlen($search, 'UTF-8') > self::MAX_SEARCH_LENGTH) {
            throw new InvalidValue(sprintf('A search is at most %d characters.', self::MAX_SEARCH_LENGTH));
        }

        return new self($page, $perPage, $search);
    }

    /** @return non-negative-int How many items come before this page. */
    public function offset(): int
    {
        return ($this->page - 1) * $this->perPage;
    }
}
