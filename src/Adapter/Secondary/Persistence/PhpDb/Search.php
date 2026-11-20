<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Shared\PageRequest;

/**
 * The `WHERE` clause and parameters of a paged search: a case-insensitive substring
 * match across some columns, with the wildcards of `LIKE` escaped.
 *
 * Without the escaping, a search for `100%` would match every row beginning with
 * `100`, and one for `_` every row — wrong in a way that is very hard to report. The
 * value is a bound parameter either way; this is about meaning, not injection.
 */
final readonly class Search
{
    /**
     * @param array<string, string> $parameters
     */
    private function __construct(
        public string $where,
        public array $parameters,
    ) {
    }

    /**
     * @param non-empty-list<string> $columns Column names written by the repository, never by a caller.
     */
    public static function across(PageRequest $request, array $columns): self
    {
        if ($request->search === '') {
            return new self('', []);
        }

        $conditions = array_map(
            static fn (string $column): string => $column . " ILIKE :search ESCAPE '\\'",
            $columns,
        );

        return new self(
            'WHERE ' . implode(' OR ', $conditions),
            ['search' => '%' . addcslashes($request->search, '\\%_') . '%'],
        );
    }

    /**
     * The parameters together with the page's `LIMIT` and `OFFSET`.
     *
     * @return array<string, string|int>
     */
    public function pageParameters(PageRequest $request): array
    {
        return $this->parameters + ['limit' => $request->perPage, 'offset' => $request->offset()];
    }
}
