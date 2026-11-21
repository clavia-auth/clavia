<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication;

use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Authentication\Event\SessionEndReason;
use Clavia\Domain\Authentication\Event\SessionsEnded;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Identity\UserId;

/**
 * End an account's browser sessions — every one, or the one a `sid` names — and say so
 * ({@see SessionsEnded}), so that back-channel logout tells the applications that signed
 * in through them.
 *
 * What an operator does from the Management API, and what happens to an account that is
 * deactivated or deleted: from then on nothing it signed in to here should still treat it
 * as signed in. Tokens already issued are not revoked — that is `/oauth2/revoke`'s job, and
 * an application told by back-channel logout gives up its own.
 */
final readonly class SignOutEverywhere
{
    public function __construct(
        private Sessions $sessions,
        private DomainEvents $events,
    ) {
    }

    /**
     * @return list<Session> The sessions ended.
     */
    public function __invoke(UserId $userId): array
    {
        $ended = $this->sessions->endEverywhere($userId);
        $this->events->dispatch(new SessionsEnded(SessionEndReason::EndedEverywhere, $ended));

        return $ended;
    }

    /**
     * @return Session|null The session ended; null when the account has none by that `sid`.
     */
    public function one(UserId $userId, string $sid): ?Session
    {
        $ended = $this->sessions->endBySid($userId, $sid);
        if ($ended !== null) {
            $this->events->dispatch(new SessionsEnded(SessionEndReason::EndedByOperator, [$ended]));
        }

        return $ended;
    }
}
