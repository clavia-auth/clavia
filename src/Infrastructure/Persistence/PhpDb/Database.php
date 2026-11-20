<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Infrastructure\Persistence\PhpDb;

use PDO;
use PhpDb\Adapter\Adapter;
use PhpDb\Adapter\Driver\ResultInterface;
use PhpDb\Pgsql\AdapterPlatform;
use PhpDb\Pgsql\Pdo\Driver;
use RuntimeException;

/**
 * The one door to PostgreSQL: every repository and the migrator go through it.
 *
 * It wraps the `php-db/phpdb` adapter so that the rest of the persistence code states
 * SQL and parameters and gets plain rows back. The library is pre-1.0; if its API
 * moves, this class moves with it and the repositories do not.
 *
 * Queries are written out, with named parameters (`:client_id`). The statements this
 * server's guarantees rest on — `SELECT … FOR UPDATE`, `INSERT … RETURNING`,
 * `UPDATE … WHERE used_at IS NULL` — are exactly the ones a query builder hides or
 * cannot express, so they stay visible. The builder remains available through
 * {@see self::adapter()} for dynamic filters and pagination.
 *
 * The connection is opened on first use: building this object costs nothing, and a
 * request that needs no database never opens one.
 */
final class Database
{
    private Adapter $adapter;

    public function __construct(PostgresUrl $url)
    {
        $connection = new PostgresConnection([
            'dsn' => $url->dsn,
            'username' => $url->username,
            'password' => $url->password,
            'driver_options' => [
                // Real server-side prepared statements: parameters never travel inside the SQL text.
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_STRINGIFY_FETCHES => false,
            ],
        ]);
        $driver = new Driver($connection);

        $this->adapter = new Adapter($driver, new AdapterPlatform($driver));
    }

    /**
     * Run a query and return every row.
     *
     * @param array<string, scalar|null> $parameters Named parameters, without the leading colon.
     *
     * @return list<array<string, mixed>>
     */
    public function fetchAll(string $sql, array $parameters = []): array
    {
        $rows = [];
        /** @var array<string, mixed> $row */
        foreach ($this->run($sql, $parameters) as $row) {
            $rows[] = $row;
        }

        return $rows;
    }

    /**
     * Run a query expected to match at most one row.
     *
     * @param array<string, scalar|null> $parameters
     *
     * @return array<string, mixed>|null The row, or null when there is none.
     */
    public function fetchOne(string $sql, array $parameters = []): ?array
    {
        return $this->fetchAll($sql, $parameters)[0] ?? null;
    }

    /**
     * Run a query and return the first column of its first row, or null when there is no row.
     *
     * @param array<string, scalar|null> $parameters
     */
    public function fetchValue(string $sql, array $parameters = []): mixed
    {
        $row = $this->fetchOne($sql, $parameters);

        return $row === null ? null : array_first($row);
    }

    /**
     * Run a statement that changes rows.
     *
     * @param array<string, scalar|null> $parameters
     *
     * @return int How many rows it affected — the answer to "did I win?" for a conditional
     *             `UPDATE … WHERE used_at IS NULL`.
     */
    public function execute(string $sql, array $parameters = []): int
    {
        return $this->run($sql, $parameters)->getAffectedRows();
    }

    /**
     * Run several statements at once, with no parameters: a migration file.
     *
     * Never give this anything built from input.
     */
    public function executeScript(string $sql): void
    {
        $this->pdo()->exec($sql);
    }

    public function beginTransaction(): void
    {
        $this->pdo()->beginTransaction();
    }

    public function commit(): void
    {
        $this->pdo()->commit();
    }

    public function rollBack(): void
    {
        $this->pdo()->rollBack();
    }

    public function inTransaction(): bool
    {
        $connection = $this->adapter->getDriver()->getConnection();

        return $connection->isConnected() && $this->pdo()->inTransaction();
    }

    /** The underlying adapter, for the SQL builder (`PhpDb\Sql\Sql`). */
    public function adapter(): Adapter
    {
        return $this->adapter;
    }

    /**
     * @param array<string, scalar|null> $parameters
     */
    private function run(string $sql, array $parameters): ResultInterface
    {
        $result = $this->adapter->createStatement($sql)->execute($parameters);
        if ($result === null) {
            throw new RuntimeException('The database driver returned no result.');
        }

        return $result;
    }

    /**
     * Transactions and scripts go straight to PDO: the library keeps its own nesting
     * counter, and this server's transaction semantics are {@see PhpDbTransactionManager}'s.
     */
    private function pdo(): PDO
    {
        $pdo = $this->adapter->getDriver()->getConnection()->connect()->getResource();
        if (! $pdo instanceof PDO) {
            throw new RuntimeException('The database connection is not a PDO connection.');
        }

        return $pdo;
    }
}
