<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Application\Management\NotFound;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/**
 * `GET /api/v1/users` and `GET /api/v1/users/{user_id}`: the queries, side by side.
 */
final readonly class ReadUsers
{
    public function __construct(private UserRepository $users)
    {
    }

    /** @return Page<User> */
    public function page(PageRequest $request): Page
    {
        return $this->users->page($request);
    }

    /**
     * @throws NotFound
     */
    public function one(UserId $id): User
    {
        return $this->users->find($id) ?? throw NotFound::of('user');
    }
}
