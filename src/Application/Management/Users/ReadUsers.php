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
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
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
    public function __construct(
        private UserRepository $users,
        private MfaFactorRepository $factors,
    ) {
    }

    /**
     * @return Page<ManagedUser>
     */
    public function page(PageRequest $request): Page
    {
        $page = $this->users->page($request);

        return new Page($this->describeAll($page->items), $page->total, $page->request);
    }

    /**
     * Several accounts with what lives beside them, in one look-up rather than one each.
     *
     * @param list<User> $users
     *
     * @return list<ManagedUser> In the order given.
     */
    public function describeAll(array $users): array
    {
        $enrolled = array_map(
            static fn (UserId $id): string => $id->value,
            $this->factors->confirmedAmong(array_map(static fn (User $user): UserId => $user->id, $users)),
        );

        return array_map(
            static fn (User $user): ManagedUser => new ManagedUser($user, in_array($user->id->value, $enrolled, true)),
            $users,
        );
    }

    /**
     * @throws NotFound
     */
    public function one(UserId $id): ManagedUser
    {
        return $this->describe($this->users->find($id) ?? throw NotFound::of('user'));
    }

    /** The account with what lives beside it. */
    public function describe(User $user): ManagedUser
    {
        return new ManagedUser($user, $this->factors->find($user->id)?->isConfirmed() ?? false);
    }
}
