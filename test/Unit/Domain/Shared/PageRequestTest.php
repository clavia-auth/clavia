<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Shared;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PageRequestTest extends TestCase
{
    public function testTheDefaultsAreTheFirstPageOfFiftyWithNoSearch(): void
    {
        $request = PageRequest::of();

        self::assertSame(1, $request->page);
        self::assertSame(50, $request->perPage);
        self::assertSame('', $request->search);
        self::assertSame(0, $request->offset());
    }

    public function testTheOffsetCountsTheItemsOfEarlierPages(): void
    {
        self::assertSame(40, PageRequest::of(3, 20)->offset());
    }

    public function testTheSearchIsTrimmed(): void
    {
        self::assertSame('alice', PageRequest::of(search: "  alice\n")->search);
    }

    /**
     * @param array{int, int, string} $arguments
     */
    #[DataProvider('outOfBounds')]
    public function testValuesOutOfBoundsAreRefused(array $arguments): void
    {
        $this->expectException(InvalidValue::class);

        PageRequest::of(...$arguments);
    }

    /** @return iterable<string, array{array{int, int, string}}> */
    public static function outOfBounds(): iterable
    {
        yield 'page 0' => [[0, 50, '']];
        yield 'no items per page' => [[1, 0, '']];
        yield 'more than a hundred per page' => [[1, 101, '']];
        yield 'a search beyond 200 characters' => [[1, 50, str_repeat('é', 201)]];
    }

    public function testAPageMapsItsItemsAndKeepsItsCount(): void
    {
        $page = new Page([1, 2], 7, PageRequest::of(2, 2));

        $mapped = $page->map(static fn (int $item): string => 'item ' . $item);

        self::assertSame(['item 1', 'item 2'], $mapped->items);
        self::assertSame(7, $mapped->total);
        self::assertSame(2, $mapped->request->page);
    }
}
