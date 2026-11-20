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
use Clavia\Infrastructure\Persistence\PhpDb\PostgresUrl;
use ClaviaTest\Support\IntegrationTestCase;
use PDOException;
use Throwable;

/**
 * Proves that `php-db/phpdb-pgsql` does what the repositories will rely on, before any
 * repository exists: parameters, types, `RETURNING`, row locks and conditional writes.
 */
final class DatabaseTest extends IntegrationTestCase
{
    private Database $db;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->db = $this->scratchConnection();
        $this->db->executeScript(<<<'SQL'
            CREATE TABLE codes (
                id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                digest     text NOT NULL UNIQUE,
                client_id  text NOT NULL,
                attempts   integer NOT NULL DEFAULT 0,
                is_active  boolean NOT NULL DEFAULT true,
                note       text,
                used_at    timestamptz,
                created_at timestamptz NOT NULL DEFAULT now()
            );
            SQL);
    }

    public function testBuildingItOpensNoConnection(): void
    {
        // Nothing listens there; only using the connection would find out.
        $unreachable = new Database(PostgresUrl::parse('postgresql://nobody@127.0.0.1:1/nothing?connect_timeout=1'));

        self::assertFalse($unreachable->inTransaction());

        $this->expectException(Throwable::class);

        $unreachable->fetchValue('SELECT 1');
    }

    public function testNamedParametersAreBoundNotInterpolated(): void
    {
        $hostile = "x'); DROP TABLE codes; --";

        $this->db->execute(
            'INSERT INTO codes (digest, client_id) VALUES (:digest, :client_id)',
            ['digest' => $hostile, 'client_id' => 'client-1'],
        );

        self::assertSame($hostile, $this->db->fetchValue('SELECT digest FROM codes'));
        self::assertSame(1, $this->db->fetchValue('SELECT count(*) FROM codes'));
    }

    public function testValuesKeepTheirTypesInBothDirections(): void
    {
        $this->db->execute(
            'INSERT INTO codes (digest, client_id, attempts, is_active, note) '
            . 'VALUES (:digest, :client_id, :attempts, :is_active, :note)',
            ['digest' => 'd1', 'client_id' => 'c', 'attempts' => 3, 'is_active' => false, 'note' => null],
        );

        $row = $this->db->fetchOne('SELECT attempts, is_active, note, used_at, digest FROM codes');

        self::assertSame(
            ['attempts' => 3, 'is_active' => false, 'note' => null, 'used_at' => null, 'digest' => 'd1'],
            $row,
        );
        self::assertSame(1, $this->db->fetchValue('SELECT count(*) FROM codes WHERE is_active = :a', ['a' => false]));
        self::assertSame(0, $this->db->fetchValue('SELECT count(*) FROM codes WHERE is_active = :a', ['a' => true]));
        self::assertSame(1, $this->db->fetchValue('SELECT count(*) FROM codes WHERE attempts > :n', ['n' => 2]));
    }

    public function testFetchingNothingIsNullOrAnEmptyList(): void
    {
        self::assertSame([], $this->db->fetchAll('SELECT * FROM codes'));
        self::assertNull($this->db->fetchOne('SELECT * FROM codes'));
        self::assertNull($this->db->fetchValue('SELECT digest FROM codes'));
    }

    public function testFetchAllReturnsEveryRowInOrder(): void
    {
        foreach (['a', 'b', 'c'] as $digest) {
            $this->db->execute("INSERT INTO codes (digest, client_id) VALUES (:d, 'c')", ['d' => $digest]);
        }

        $rows = $this->db->fetchAll('SELECT digest FROM codes ORDER BY digest DESC');

        self::assertSame([['digest' => 'c'], ['digest' => 'b'], ['digest' => 'a']], $rows);
    }

    public function testInsertReturningGivesBackWhatTheDatabaseGenerated(): void
    {
        $first = $this->db->fetchOne(
            "INSERT INTO codes (digest, client_id) VALUES (:d, 'c') RETURNING id, created_at",
            ['d' => 'first'],
        );
        $second = $this->db->fetchValue(
            "INSERT INTO codes (digest, client_id) VALUES (:d, 'c') RETURNING id",
            ['d' => 'second'],
        );

        self::assertNotNull($first);
        self::assertSame(1, $first['id']);
        self::assertIsString($first['created_at']);
        self::assertSame(2, $second);
    }

    public function testExecuteReportsHowManyRowsChanged(): void
    {
        foreach (['a', 'b', 'c'] as $digest) {
            $this->db->execute("INSERT INTO codes (digest, client_id) VALUES (:d, 'c')", ['d' => $digest]);
        }

        self::assertSame(3, $this->db->execute('UPDATE codes SET attempts = attempts + 1'));
        self::assertSame(1, $this->db->execute('DELETE FROM codes WHERE digest = :d', ['d' => 'a']));
        self::assertSame(0, $this->db->execute('DELETE FROM codes WHERE digest = :d', ['d' => 'gone']));
    }

    public function testAConditionalUpdateSpendsSomethingExactlyOnce(): void
    {
        $this->db->execute("INSERT INTO codes (digest, client_id) VALUES ('code', 'c')");
        $spend = 'UPDATE codes SET used_at = now() WHERE digest = :d AND used_at IS NULL';
        $other = $this->scratchConnection();

        // Two sessions race to redeem the same code; the affected-row count names the winner.
        self::assertSame(1, $this->db->execute($spend, ['d' => 'code']));
        self::assertSame(0, $other->execute($spend, ['d' => 'code']));
    }

    public function testUpdateReturningSpendsAndReadsInOneStatement(): void
    {
        $this->db->execute("INSERT INTO codes (digest, client_id) VALUES ('code', 'client-7')");
        $spend = 'UPDATE codes SET used_at = now() WHERE digest = :d AND used_at IS NULL RETURNING client_id';

        self::assertSame(['client_id' => 'client-7'], $this->db->fetchOne($spend, ['d' => 'code']));
        self::assertNull($this->db->fetchOne($spend, ['d' => 'code']));
    }

    public function testARowLockedForUpdateCannotBeLockedByAnotherSessionUntilCommit(): void
    {
        $this->db->execute("INSERT INTO codes (digest, client_id) VALUES ('token', 'c')");
        $other = $this->scratchConnection();
        $lock = 'SELECT id FROM codes WHERE digest = :d FOR UPDATE';

        $this->db->beginTransaction();
        self::assertNotNull($this->db->fetchOne($lock, ['d' => 'token']));

        // The second session neither waits forever nor gets the row: NOWAIT fails at once…
        $other->beginTransaction();
        try {
            $other->fetchOne($lock . ' NOWAIT', ['d' => 'token']);
            self::fail('A second session locked a row that was already locked.');
        } catch (Throwable $refusal) {
            self::assertSame('55P03', $this->sqlState($refusal), 'expected lock_not_available');
        }
        $other->rollBack();

        // …and SKIP LOCKED sees no row at all.
        self::assertNull($other->fetchOne($lock . ' SKIP LOCKED', ['d' => 'token']));

        $this->db->commit();

        // Once the first transaction ends, the row is available again.
        $other->beginTransaction();
        self::assertNotNull($other->fetchOne($lock . ' NOWAIT', ['d' => 'token']));
        $other->commit();
    }

    public function testALockHolderSeesItsOwnWriteAndOthersSeeItOnlyAfterCommit(): void
    {
        $this->db->execute("INSERT INTO codes (digest, client_id) VALUES ('token', 'c')");
        $other = $this->scratchConnection();
        $attempts = 'SELECT attempts FROM codes WHERE digest = :d';

        $this->db->beginTransaction();
        $this->db->fetchOne($attempts . ' FOR UPDATE', ['d' => 'token']);
        $this->db->execute('UPDATE codes SET attempts = 5 WHERE digest = :d', ['d' => 'token']);

        self::assertSame(5, $this->db->fetchValue($attempts, ['d' => 'token']));
        self::assertSame(0, $other->fetchValue($attempts, ['d' => 'token']));

        $this->db->commit();

        self::assertSame(5, $other->fetchValue($attempts, ['d' => 'token']));
    }

    public function testReadingInsideATransactionDoesNotDiscardItsWrites(): void
    {
        // A session that has never touched a sequence: the library's own "last generated
        // value" lookup (SELECT LASTVAL()) fails here, and inside a transaction a failed
        // statement poisons everything before it. See PostgresConnection.
        $fresh = $this->scratchConnection();
        $fresh->executeScript('CREATE TABLE plain (v text PRIMARY KEY)');

        $fresh->beginTransaction();
        $fresh->execute("INSERT INTO plain (v) VALUES ('kept')");
        self::assertSame('kept', $fresh->fetchValue('SELECT v FROM plain'));
        self::assertSame(1, $fresh->execute("UPDATE plain SET v = 'kept' WHERE v = 'kept'"));
        $fresh->commit();

        self::assertSame('kept', $this->db->fetchValue('SELECT v FROM plain'));
    }

    public function testTheQueryBuilderDoesNotDiscardATransactionEither(): void
    {
        $fresh = $this->scratchConnection();
        $fresh->executeScript('CREATE TABLE plain (v text PRIMARY KEY)');
        $sql = new \PhpDb\Sql\Sql($fresh->adapter());

        $fresh->beginTransaction();
        $sql->prepareStatementForSqlObject($sql->insert('plain')->values(['v' => 'built']))->execute();
        $sql->prepareStatementForSqlObject($sql->select('plain'))->execute();
        $fresh->commit();

        self::assertSame('built', $this->db->fetchValue('SELECT v FROM plain'));
    }

    public function testAUniqueViolationCarriesItsSqlState(): void
    {
        $insert = "INSERT INTO codes (digest, client_id) VALUES (:d, 'c')";
        $this->db->execute($insert, ['d' => 'same']);

        try {
            $this->db->execute($insert, ['d' => 'same']);
            self::fail('A duplicate digest was accepted.');
        } catch (Throwable $violation) {
            self::assertSame('23505', $this->sqlState($violation), 'expected unique_violation');
        }
    }

    public function testAScriptRunsSeveralStatements(): void
    {
        $this->db->executeScript(<<<'SQL'
            CREATE TABLE one (id integer PRIMARY KEY);
            CREATE TABLE two (id integer PRIMARY KEY REFERENCES one (id));
            INSERT INTO one VALUES (1);
            INSERT INTO two VALUES (1);
            SQL);

        self::assertSame(1, $this->db->fetchValue('SELECT count(*) FROM two'));
    }

    public function testTheQueryBuilderIsAvailableForDynamicQueries(): void
    {
        $this->db->execute("INSERT INTO codes (digest, client_id) VALUES ('a', 'c1'), ('b', 'c2')");

        $sql = new \PhpDb\Sql\Sql($this->db->adapter());
        $select = $sql->select('codes')->columns(['digest'])->where(['client_id' => 'c2']);
        $rows = iterator_to_array($sql->prepareStatementForSqlObject($select)->execute() ?? []);

        self::assertSame([['digest' => 'b']], $rows);
    }

    /** The five-character SQLSTATE behind a failed statement, wherever the library wrapped it. */
    private function sqlState(Throwable $failure): ?string
    {
        for ($cause = $failure; $cause !== null; $cause = $cause->getPrevious()) {
            if ($cause instanceof PDOException) {
                return (string) $cause->getCode();
            }
        }

        return null;
    }
}
