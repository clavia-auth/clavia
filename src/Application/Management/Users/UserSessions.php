<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignOutEverywhere;
use Clavia\Application\Management\NotFound;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;

/**
 * `GET|DELETE /api/v1/users/{user_id}/sessions` and `DELETE …/sessions/{sid}`: an
 * account's browser sessions at `auth.*`, and signing it out of them — everywhere, or
 * one by the `sid` its ID tokens carry.
 *
 * Device approvals are not sessions and are not here: a device holds tokens, which
 * `/oauth2/revoke` ends.
 */
final readonly class UserSessions
{
    public function __construct(
        private UserRepository $users,
        private ClientRepository $clients,
        private Sessions $sessions,
        private SignOutEverywhere $signOut,
    ) {
    }

    /**
     * @return list<ManagedSession> Oldest first.
     *
     * @throws NotFound
     */
    public function of(UserId $userId): array
    {
        $this->users->find($userId) ?? throw NotFound::of('user');

        $managed = [];
        foreach ($this->sessions->of($userId) as $session) {
            $clients = [];
            foreach ($session->clients as $clientId) {
                $client = $this->clients->find($clientId);
                if ($client instanceof Client) {
                    $clients[] = $client;
                }
            }
            $managed[] = new ManagedSession($session, $clients);
        }

        return $managed;
    }

    /**
     * Sign the account out everywhere. Idempotent: an account with no session is already
     * signed out everywhere.
     *
     * @throws NotFound
     */
    public function endAll(UserId $userId): void
    {
        $this->users->find($userId) ?? throw NotFound::of('user');

        ($this->signOut)($userId);
    }

    /**
     * @throws NotFound When the account, or a current session of it by that `sid`, does not exist.
     */
    public function end(UserId $userId, string $sid): void
    {
        $this->users->find($userId) ?? throw NotFound::of('user');

        if ($this->signOut->one($userId, $sid) === null) {
            throw NotFound::of('session');
        }
    }
}
