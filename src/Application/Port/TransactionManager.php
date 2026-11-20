<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

/**
 * Runs a use case as one unit of work: everything it wrote is kept, or none of it is.
 *
 * Transactions are an application concern — a use case says where the boundary is; the
 * persistence adapter decides what that means. This is what makes the server's
 * exactly-once promises hold: redeeming an authorization code or rotating a refresh
 * token reads a row under a lock, decides, and writes, and a concurrent attempt must
 * see either none of that or all of it.
 */
interface TransactionManager
{
    /**
     * Run `$work` inside a transaction and return what it returns.
     *
     * Commits when `$work` returns; rolls back and rethrows when it throws. A call made
     * while a transaction is already open joins it — there is one transaction, the
     * outermost call owns it, and an exception anywhere inside undoes all of it.
     *
     * @template T
     *
     * @param callable(): T $work
     *
     * @return T
     */
    public function transactional(callable $work): mixed;
}
