<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\SignIn;

use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserRepository;

/**
 * Check an email and a password and, when they match an active account, start a session.
 *
 * Every failure takes the same time and gives the same answer. When no account could
 * match, a verification is still simulated, so how fast the server answers does not
 * say whether an address has an account. A throttled subject is refused without the
 * password being looked at — that is the point of the throttle — and refused the same
 * way.
 */
final readonly class SignInWithPassword
{
    public function __construct(
        private UserRepository $users,
        private PasswordHasher $hasher,
        private LoginThrottle $throttle,
        private LoginStateStore $loginStates,
        private Sessions $sessions,
    ) {
    }

    public function __invoke(PasswordSignIn $attempt): SignInOutcome
    {
        $user = $this->authenticate($attempt);
        if ($user === null) {
            return new CredentialsRejected();
        }

        // The handle has done its job once the person is authenticated: forgotten now
        // rather than left to expire, in the same single-use spirit as a spent code.
        $pending = $attempt->loginState === null || $attempt->loginState === ''
            ? null
            : $this->loginStates->get($attempt->loginState);
        if ($attempt->loginState !== null && $attempt->loginState !== '') {
            $this->loginStates->forget($attempt->loginState);
        }

        // Re-validated even though it came from this server's own store.
        $nextUrl = LocalPath::orDefault($pending?->nextUrl)->value;

        $sessionId = $this->sessions->establish(
            $user->id,
            [AuthenticationMethod::Password],
            $attempt->currentSessionId,
        );

        return new SignedIn($sessionId, $nextUrl);
    }

    private function authenticate(PasswordSignIn $attempt): ?User
    {
        if ($this->throttle->isThrottled($attempt->email, $attempt->clientAddress)) {
            $this->hasher->simulateVerification($attempt->password);

            return null;
        }

        $user = $attempt->email === '' ? null : $this->users->findByEmail($attempt->email);
        $hash = $user?->passwordHash();

        if ($user === null || $hash === null || ! $user->isActive()) {
            $this->hasher->simulateVerification($attempt->password);
            $this->throttle->recordFailure($attempt->email, $attempt->clientAddress);

            return null;
        }

        if (! $this->hasher->verify($attempt->password, $hash)) {
            $this->throttle->recordFailure($attempt->email, $attempt->clientAddress);

            return null;
        }

        $this->throttle->reset($attempt->email, $attempt->clientAddress);

        return $user;
    }
}
