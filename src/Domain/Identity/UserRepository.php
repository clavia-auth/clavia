<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/**
 * Where user accounts are kept.
 */
interface UserRepository
{
    public function find(UserId $id): ?User;

    /** Look an account up by the exact address it was registered with. */
    public function findByEmail(string $email): ?User;

    /**
     * Every account whose address equals `$email` ignoring case — usually none or one.
     * Addresses are unique as written, so two accounts can differ only by case; a caller
     * linking by address treats more than one as no answer.
     *
     * @return list<User>
     */
    public function matchingEmail(string $email): array;

    /**
     * Insert the account, or update it when it already exists.
     *
     * @throws AlreadyExists When another account uses the address.
     */
    public function save(User $user): void;

    /**
     * Remove the account, and with it every code and token issued on its behalf.
     */
    public function delete(UserId $id): void;

    /**
     * Accounts newest first, searching the email address — the one thing an operator has
     * to hand when a support request arrives.
     *
     * @return Page<User>
     */
    public function page(PageRequest $request): Page;
}
