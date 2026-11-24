<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/**
 * Where user accounts are kept.
 */
interface UserRepository
{
    public function find(UserId $id): ?User;

    /** Look an account up by the exact address it was registered with, in its connection. */
    public function findByEmail(ConnectionName $connection, string $email): ?User;

    /**
     * Every account in one of `$connections` whose address equals `$email` ignoring case,
     * oldest first. Several are normal — the same address in two pools is two accounts —
     * and a caller linking by address treats more than one as no answer.
     *
     * @param list<ConnectionName> $connections
     *
     * @return list<User>
     */
    public function matchingEmail(string $email, array $connections): array;

    /** How many accounts belong to the connection. */
    public function countIn(ConnectionName $connection): int;

    /**
     * Insert the account, or update it when it already exists.
     *
     * @throws AlreadyExists When another account in its connection uses the address.
     */
    public function save(User $user): void;

    /**
     * Remove the account, and with it every code and token issued on its behalf.
     */
    public function delete(UserId $id): void;

    /**
     * The accounts of one connection by id, after `$after`: a walk through all of them, a page at a
     * time, that an account made or deleted meanwhile never throws off (an export).
     *
     * @param positive-int $limit
     *
     * @return list<User>
     */
    public function inConnection(ConnectionName $connection, ?UserId $after, int $limit): array;

    /**
     * Accounts newest first, searching the email address — the one thing an operator has
     * to hand when a support request arrives.
     *
     * @return Page<User>
     */
    public function page(PageRequest $request): Page;
}
