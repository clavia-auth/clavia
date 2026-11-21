<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Application\Authentication\SignOutEverywhere;
use Clavia\Application\Management\Caller\ManagementCaller;
use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Identity\Event\UserDeleted;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;

/**
 * `DELETE /api/v1/users/{user_id}`: the account, and with it every code and token
 * issued on its behalf, and its browser sessions — whose applications are told
 * (Back-Channel Logout 1.0).
 */
final readonly class DeleteUser
{
    public function __construct(
        private UserRepository $users,
        private SignOutEverywhere $signOut,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound
     * @throws Conflict When it is the account the caller is acting as: the token making the
     *                  request would be left authenticating for an account that no longer exists.
     */
    public function __invoke(UserId $id, ManagementCaller $caller): void
    {
        $user = $this->users->find($id) ?? throw NotFound::of('user');
        if ($caller->isActingAs($user->id)) {
            throw new Conflict('A token cannot delete the account it is acting as.');
        }

        ($this->signOut)($user->id);
        $this->users->delete($user->id);
        $this->events->dispatch(new UserDeleted($user));
    }
}
