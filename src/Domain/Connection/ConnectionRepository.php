<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection;

use Clavia\Domain\Shared\AlreadyExists;

/**
 * Every connection — the built-in ones seeded by the schema, the pools and providers an
 * operator added.
 */
interface ConnectionRepository
{
    public function find(ConnectionName $name): ?Connection;

    /**
     * Every connection, by name. There are few: a deployment's ways to sign in.
     *
     * @return list<Connection>
     */
    public function all(): array;

    /**
     * Store a new connection.
     *
     * @throws AlreadyExists When the name is taken.
     */
    public function add(Connection $connection): void;

    /** Store the changes to an existing connection. */
    public function save(Connection $connection): void;

    /**
     * Delete it. Applications stop enabling it. Refused by the storage while an account
     * belongs to it or an identity is linked through it — check first, for a message.
     */
    public function delete(ConnectionName $name): void;
}
