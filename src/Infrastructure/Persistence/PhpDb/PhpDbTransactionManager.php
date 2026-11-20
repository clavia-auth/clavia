<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Infrastructure\Persistence\PhpDb;

use Clavia\Application\Port\TransactionManager;
use Throwable;

/**
 * One PostgreSQL transaction per outermost {@see self::transactional()} call.
 *
 * A nested call joins the transaction already open instead of opening a savepoint:
 * there is one unit of work, and an exception anywhere in it undoes all of it. PostgreSQL
 * agrees — after a failed statement the transaction accepts nothing but a rollback — so
 * "catch and carry on" inside a transaction is not something a use case may do.
 *
 * Isolation is PostgreSQL's default, READ COMMITTED. Exactly-once operations do not
 * rely on a stricter level; they take a row lock (`SELECT … FOR UPDATE`) or make the
 * write itself conditional.
 */
final readonly class PhpDbTransactionManager implements TransactionManager
{
    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function transactional(callable $work): mixed
    {
        if ($this->database->inTransaction()) {
            return $work();
        }

        $this->database->beginTransaction();

        try {
            $result = $work();
        } catch (Throwable $failure) {
            try {
                $this->database->rollBack();
            } catch (Throwable) {
                // The connection is gone or the transaction already ended; the original
                // failure is the one worth reporting, and PostgreSQL discards an
                // unfinished transaction when the connection closes.
            }

            throw $failure;
        }

        $this->database->commit();

        return $result;
    }
}
