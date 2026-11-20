<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Persistence;

use Clavia\Infrastructure\Persistence\PhpDb\Database;
use Clavia\Infrastructure\Persistence\PhpDb\PhpDbTransactionManager;
use ClaviaTest\Support\IntegrationTestCase;
use RuntimeException;
use Throwable;

final class PhpDbTransactionManagerTest extends IntegrationTestCase
{
    private Database $db;

    private Database $observer;

    private PhpDbTransactionManager $transactions;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->db = $this->scratchConnection();
        $this->observer = $this->scratchConnection();
        $this->transactions = new PhpDbTransactionManager($this->db);
        $this->db->executeScript('CREATE TABLE ledger (entry text PRIMARY KEY)');
    }

    public function testItCommitsWhenTheWorkReturnsAndHandsBackItsResult(): void
    {
        $result = $this->transactions->transactional(function (): mixed {
            $this->write('a');

            return $this->db->fetchValue('SELECT count(*) FROM ledger');
        });

        self::assertSame(1, $result);
        self::assertSame(['a'], $this->committedEntries());
        self::assertFalse($this->db->inTransaction());
    }

    public function testNothingIsVisibleToOthersUntilTheWorkReturns(): void
    {
        $this->transactions->transactional(function (): void {
            $this->write('a');

            self::assertTrue($this->db->inTransaction());
            self::assertSame([], $this->committedEntries());
        });

        self::assertSame(['a'], $this->committedEntries());
    }

    public function testAnExceptionUndoesEverythingAndIsRethrown(): void
    {
        try {
            $this->transactions->transactional(function (): void {
                $this->write('a');
                $this->write('b');

                throw new RuntimeException('the use case refused');
            });
            self::fail('The exception was swallowed.');
        } catch (RuntimeException $failure) {
            self::assertSame('the use case refused', $failure->getMessage());
        }

        self::assertSame([], $this->committedEntries());
        self::assertFalse($this->db->inTransaction());
    }

    public function testAFailedStatementUndoesTheWritesBeforeIt(): void
    {
        $refused = false;
        try {
            $this->transactions->transactional(function (): void {
                $this->write('a');
                $this->write('a'); // primary key violation
            });
        } catch (Throwable) {
            $refused = true;
        }

        self::assertTrue($refused, 'A duplicate key was accepted.');
        self::assertSame([], $this->committedEntries());
        self::assertFalse($this->db->inTransaction());
    }

    public function testANestedCallJoinsTheOuterTransaction(): void
    {
        $this->transactions->transactional(function (): void {
            $this->write('outer');

            $inner = $this->transactions->transactional(function (): mixed {
                $this->write('inner');

                return $this->db->fetchValue('SELECT count(*) FROM ledger');
            });

            self::assertSame(2, $inner);
            // The inner call returning commits nothing: there is one transaction.
            self::assertSame([], $this->committedEntries());
            self::assertTrue($this->db->inTransaction());
        });

        self::assertSame(['inner', 'outer'], $this->committedEntries());
    }

    public function testAnExceptionInANestedCallUndoesTheOuterWorkToo(): void
    {
        try {
            $this->transactions->transactional(function (): void {
                $this->write('outer');
                $this->transactions->transactional(function (): void {
                    $this->write('inner');

                    throw new RuntimeException('inner failure');
                });
            });
            self::fail('The exception was swallowed.');
        } catch (RuntimeException $failure) {
            self::assertSame('inner failure', $failure->getMessage());
        }

        self::assertSame([], $this->committedEntries());
    }

    public function testTheConnectionIsUsableAgainAfterARollback(): void
    {
        try {
            $this->transactions->transactional(function (): void {
                $this->write('a');
                $this->write('a');
            });
        } catch (Throwable) {
            // expected
        }

        $this->transactions->transactional(fn () => $this->write('after'));

        self::assertSame(['after'], $this->committedEntries());
    }

    public function testARowLockTakenInsideIsReleasedWhenTheTransactionEnds(): void
    {
        $this->write('row');
        $lock = "SELECT entry FROM ledger WHERE entry = 'row' FOR UPDATE NOWAIT";

        $this->transactions->transactional(function () use ($lock): void {
            $this->db->fetchOne($lock);

            $locked = false;
            try {
                $this->observer->fetchOne($lock);
            } catch (Throwable) {
                $locked = true;
            }

            self::assertTrue($locked, 'The row was not locked inside the transaction.');
        });

        self::assertSame(['entry' => 'row'], $this->observer->fetchOne($lock));
    }

    private function write(string $entry): void
    {
        $this->db->execute('INSERT INTO ledger (entry) VALUES (:entry)', ['entry' => $entry]);
    }

    /**
     * What another session sees: only what has been committed.
     *
     * @return list<mixed>
     */
    private function committedEntries(): array
    {
        return array_column($this->observer->fetchAll('SELECT entry FROM ledger ORDER BY entry'), 'entry');
    }
}
