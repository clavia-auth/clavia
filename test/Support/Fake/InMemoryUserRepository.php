<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;

/**
 * Users kept in an array. Stores and returns copies, like a database would: changing an
 * object after saving it, or one that was fetched, changes nothing until it is saved.
 */
final class InMemoryUserRepository implements UserRepository
{
    /** @var array<string, User> */
    private array $users = [];

    #[\Override]
    public function find(UserId $id): ?User
    {
        return isset($this->users[$id->value]) ? clone $this->users[$id->value] : null;
    }

    #[\Override]
    public function findByEmail(string $email): ?User
    {
        $match = array_find($this->users, static fn (User $user): bool => $user->email === $email);

        return $match === null ? null : clone $match;
    }

    #[\Override]
    public function save(User $user): void
    {
        $this->users[$user->id->value] = clone $user;
    }
}
