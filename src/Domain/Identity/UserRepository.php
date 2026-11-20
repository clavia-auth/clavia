<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

/**
 * Where user accounts are kept.
 */
interface UserRepository
{
    public function find(UserId $id): ?User;

    /** Look an account up by the exact address it was registered with. */
    public function findByEmail(string $email): ?User;

    /** Insert the account, or update it when it already exists. */
    public function save(User $user): void;
}
