<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use DateTimeImmutable;

/**
 * Paging over an in-memory collection the way the PostgreSQL repositories page: a
 * case-insensitive, literal substring match on some fields, newest first, ties broken
 * by identifier.
 */
final class InMemoryPaging
{
    private function __construct()
    {
    }

    /**
     * @template T
     * @param list<T>                                    $items
     * @param callable(T): list<string>                  $searchable
     * @param callable(T): array{DateTimeImmutable, string} $sortKey Creation instant and identifier.
     * @return Page<T>
     */
    public static function page(array $items, PageRequest $request, callable $searchable, callable $sortKey): Page
    {
        $matching = [];
        $keys = [];
        foreach ($items as $item) {
            if ($request->search === '' || self::matches($searchable($item), $request->search)) {
                $matching[] = $item;
                $keys[] = $sortKey($item);
            }
        }

        // Newest first; among equals, by identifier.
        $order = array_keys($matching);
        usort($order, static fn (int $a, int $b): int => [$keys[$b][0], $keys[$a][1]] <=> [$keys[$a][0], $keys[$b][1]]);
        $items = array_map(static fn (int $index): mixed => $matching[$index], $order);

        return new Page(array_slice($items, $request->offset(), $request->perPage), count($items), $request);
    }

    /**
     * @param list<string> $fields
     */
    private static function matches(array $fields, string $search): bool
    {
        foreach ($fields as $field) {
            if (mb_stripos($field, $search) !== false) {
                return true;
            }
        }

        return false;
    }
}
