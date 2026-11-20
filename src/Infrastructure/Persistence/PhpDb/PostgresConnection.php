<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Infrastructure\Persistence\PhpDb;

use PhpDb\Pgsql\Pdo\Connection;

/**
 * The library's PDO connection, minus one query that breaks transactions.
 *
 * After every statement, `php-db/phpdb-pgsql` (at the pinned commit) asks the connection
 * for the "last generated value", which on PostgreSQL runs `SELECT LASTVAL()`. In a
 * session that has not used a sequence yet that query is an error. The library swallows
 * the exception — but PostgreSQL has already marked the surrounding transaction as
 * failed, so everything written before it is discarded and the eventual `COMMIT` quietly
 * becomes a `ROLLBACK`. Reads inside a transaction were enough to lose its writes.
 *
 * Nothing here needs that value: generated keys are read with `INSERT … RETURNING`,
 * which is atomic and names the column. So the lookup is answered without asking the
 * server, unless a sequence is named explicitly.
 *
 * `DatabaseTest::testReadingInsideATransactionDoesNotDiscardItsWrites` pins this down;
 * if a later version of the library fixes it, this class can go.
 *
 * @psalm-suppress PropertyNotSetInConstructor The parent sets its properties when it connects.
 */
final class PostgresConnection extends Connection
{
    /**
     * @param string|null $name A sequence to read with `currval()`; without one, nothing is queried.
     */
    #[\Override]
    public function getLastGeneratedValue($name = null): string|int|false
    {
        return $name === null ? false : parent::getLastGeneratedValue($name);
    }
}
