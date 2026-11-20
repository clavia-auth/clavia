<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\TransactionManager;
use Throwable;

/**
 * A transaction manager with nothing behind it, for use cases tested against in-memory
 * repositories.
 *
 * It keeps count, so a test can assert that a use case opened exactly one unit of work
 * and whether it was committed or abandoned. It cannot undo what in-memory repositories
 * recorded; a test that needs rollback to actually roll back is an integration test.
 */
final class InMemoryTransactionManager implements TransactionManager
{
    public int $committed = 0;

    public int $rolledBack = 0;

    private int $depth = 0;

    #[\Override]
    public function transactional(callable $work): mixed
    {
        $this->depth++;

        try {
            $result = $work();
        } catch (Throwable $failure) {
            if (--$this->depth === 0) {
                $this->rolledBack++;
            }

            throw $failure;
        }

        if (--$this->depth === 0) {
            $this->committed++;
        }

        return $result;
    }

    public function isActive(): bool
    {
        return $this->depth > 0;
    }
}
