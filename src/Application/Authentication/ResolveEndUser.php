<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication;

use Clavia\Domain\Identity\UserRepository;

/**
 * Who is driving the current browser request, if anyone.
 *
 * The single place that answers it, so the authorization endpoint and the pages never
 * have to know how authentication happened. The answer comes from the session; the
 * development auto-login is consulted only when there is no signed-in user.
 */
final readonly class ResolveEndUser
{
    public function __construct(
        private Sessions $sessions,
        private UserRepository $users,
        private DevelopmentAutoLogin $autoLogin,
    ) {
    }

    /**
     * @param string|null $sessionId The identifier the browser's session cookie carries.
     */
    public function __invoke(#[\SensitiveParameter] ?string $sessionId): ?EndUser
    {
        $session = $this->sessions->resolve($sessionId);

        if ($session !== null) {
            // Re-checked on every request rather than trusted from sign-in time: an
            // account deactivated mid-session must stop being able to authorize anything.
            $user = $this->users->find($session->userId);
            if ($user !== null && $user->isActive()) {
                return new EndUser($user->id, $session);
            }
        }

        return $this->autoLogin->endUser();
    }
}
