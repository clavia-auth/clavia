<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication;

use Clavia\Application\Port\SessionStore;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * The one place a browser session is started, looked up and ended.
 *
 * Keeping all three here is what keeps the lifetimes, the rotation on sign-in and the
 * sliding of the idle window from drifting apart between the flows that use them
 * (password today; a second factor, external providers and passwordless later).
 */
final readonly class Sessions
{
    /**
     * @param positive-int $idleLifetime     Seconds a session may sit unused (`CLAVIA_SESSION_IDLE_LIFETIME`).
     * @param positive-int $absoluteLifetime Seconds a session lasts however it is used
     *                                       (`CLAVIA_SESSION_ABSOLUTE_LIFETIME`).
     */
    public function __construct(
        private SessionStore $store,
        private SecretGenerator $secrets,
        private Clock $clock,
        private int $idleLifetime,
        private int $absoluteLifetime,
    ) {
    }

    /**
     * Start a session for someone who has just authenticated, ending the one the browser
     * already held.
     *
     * The rotation is the defence against session fixation: an attacker who planted a
     * known identifier in a victim's browser must not hold a valid session once the
     * victim signs in.
     *
     * @param list<AuthenticationMethod> $methods
     * @param string|null                $replacing The identifier the browser presented, if any.
     *
     * @return non-empty-string The new identifier: the only copy outside the browser's cookie.
     */
    public function establish(UserId $userId, array $methods, #[\SensitiveParameter] ?string $replacing): string
    {
        $this->end($replacing);

        $now = $this->clock->now();
        $session = Session::establish($userId, $methods, $this->secrets->token(), $now, $this->absoluteLifetime);
        $sessionId = $this->secrets->token();

        $this->store->save($sessionId, $session, $session->idleWindowAt($now, $this->idleLifetime));

        return $sessionId;
    }

    /**
     * The session the browser's identifier names, if it is current — and, since this is
     * a use of it, its idle window starts over.
     *
     * Null for anything not current: unknown, idle too long, or past its absolute
     * ceiling. A session past the ceiling is deleted rather than renewed.
     */
    public function resolve(#[\SensitiveParameter] ?string $sessionId): ?Session
    {
        if ($sessionId === null || $sessionId === '') {
            return null;
        }

        $session = $this->store->find($sessionId);
        if ($session === null) {
            return null;
        }

        $now = $this->clock->now();
        if ($session->isExpiredAt($now)) {
            $this->store->delete($sessionId);

            return null;
        }

        $this->store->extend($sessionId, $session->idleWindowAt($now, $this->idleLifetime));

        return $session;
    }

    /**
     * End a session, returning what it was. Safe with an unknown or missing identifier.
     */
    public function end(#[\SensitiveParameter] ?string $sessionId): ?Session
    {
        if ($sessionId === null || $sessionId === '') {
            return null;
        }

        $session = $this->store->find($sessionId);
        $this->store->delete($sessionId);

        return $session;
    }
}
