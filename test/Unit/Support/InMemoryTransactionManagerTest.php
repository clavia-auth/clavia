<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class InMemoryTransactionManagerTest extends TestCase
{
    public function testItReturnsWhatTheWorkReturnsAndCountsOneCommit(): void
    {
        $transactions = new InMemoryTransactionManager();

        $result = $transactions->transactional(static fn (): int => random_int(7, 7));

        self::assertSame(7, $result);
        self::assertSame(1, $transactions->committed);
        self::assertSame(0, $transactions->rolledBack);
        self::assertFalse($transactions->isActive());
    }

    public function testANestedCallJoinsTheOuterUnitOfWork(): void
    {
        $transactions = new InMemoryTransactionManager();

        $transactions->transactional(static function () use ($transactions): void {
            self::assertTrue($transactions->isActive());
            $transactions->transactional(static fn (): null => null);
            self::assertSame(0, $transactions->committed);
        });

        self::assertSame(1, $transactions->committed);
    }

    public function testAnExceptionAbandonsTheUnitOfWorkAndIsRethrown(): void
    {
        $transactions = new InMemoryTransactionManager();

        try {
            $transactions->transactional(static fn () => throw new RuntimeException('boom'));
            self::fail('The exception was swallowed.');
        } catch (RuntimeException $failure) {
            self::assertSame('boom', $failure->getMessage());
        }

        self::assertSame(0, $transactions->committed);
        self::assertSame(1, $transactions->rolledBack);
        self::assertFalse($transactions->isActive());
    }
}
