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
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserRepository;

/**
 * Check an email and a password and, when they match an active account, start a session —
 * or, when the account has a confirmed second factor, a challenge for it instead: a
 * correct password alone is then not a sign-in ({@see CompleteFirstFactor}).
 *
 * Accounts are looked for in the pools the application signs people in from, and only
 * there. One that enables no pool cannot be signed in to with a password at all
 * ({@see PasswordSignInUnavailable}), decided before the password is looked at. Several
 * pools may hold the same address — a customer and an employee — and they are different
 * accounts: the one whose password verifies is the one signing in.
 *
 * Every failure takes the same time and gives the same answer. When no account could
 * match, a verification is still simulated, so how fast the server answers does not
 * say whether an address has an account — nor in how many pools. A throttled subject is
 * refused without the password being looked at — that is the point of the throttle — and
 * refused the same way.
 */
final readonly class SignInWithPassword
{
    public function __construct(
        private UserRepository $users,
        private PasswordHasher $hasher,
        private LoginThrottle $throttle,
        private LoginStateStore $loginStates,
        private ClientRepository $clients,
        private ConnectionAccess $access,
        private CompleteFirstFactor $completeFirstFactor,
    ) {
    }

    public function __invoke(PasswordSignIn $attempt): SignInOutcome
    {
        $pending = $this->pending($attempt->loginState);
        $clientId = $pending?->clientId;
        $client = $clientId === null ? null : $this->clients->find($clientId);
        $pools = $this->access->pools($client);
        if ($pools === []) {
            return new PasswordSignInUnavailable();
        }

        $user = $this->authenticate($attempt, $pools);
        if ($user === null) {
            return new CredentialsRejected();
        }

        // The handle has done its job once the person is authenticated: forgotten now
        // rather than left to expire, in the same single-use spirit as a spent code.
        if ($attempt->loginState !== null && $attempt->loginState !== '') {
            $this->loginStates->forget($attempt->loginState);
        }

        // Re-validated even though it came from this server's own store.
        $nextUrl = LocalPath::orDefault($pending?->nextUrl)->value;

        return ($this->completeFirstFactor)(
            $user->id,
            [AuthenticationMethod::Password],
            // The pool the account lives in, not "a password": an application that enables
            // another pool must not accept the session.
            $user->connection,
            $nextUrl,
            $pending?->clientId,
            $attempt->currentSessionId,
        );
    }

    private function pending(#[\SensitiveParameter] ?string $loginState): ?LoginState
    {
        return $loginState === null || $loginState === '' ? null : $this->loginStates->get($loginState);
    }

    /**
     * @param non-empty-list<ConnectionName> $pools
     */
    private function authenticate(PasswordSignIn $attempt, array $pools): ?User
    {
        if ($this->throttle->isThrottled($attempt->email, $attempt->clientAddress)) {
            $this->hasher->simulateVerification($attempt->password);

            return null;
        }

        $candidates = [];
        if ($attempt->email !== '') {
            foreach ($pools as $pool) {
                $user = $this->users->findByEmail($pool, $attempt->email);
                if ($user !== null && $user->isActive() && $user->passwordHash() !== null) {
                    $candidates[] = $user;
                }
            }
        }

        if ($candidates === []) {
            $this->hasher->simulateVerification($attempt->password);
            $this->throttle->recordFailure($attempt->email, $attempt->clientAddress);

            return null;
        }

        foreach ($candidates as $candidate) {
            if ($this->hasher->verify($attempt->password, (string) $candidate->passwordHash())) {
                $this->throttle->reset($attempt->email, $attempt->clientAddress);

                return $candidate;
            }
        }

        // A wrong password against every candidate is one failure.
        $this->throttle->recordFailure($attempt->email, $attempt->clientAddress);

        return null;
    }
}
