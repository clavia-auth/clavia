<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passwordless;

use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Authentication\PasswordlessChallenge;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;

/**
 * The proof held — the code was right, or the link confirmed — and the challenge is
 * spent: sign the person in.
 *
 * Passwordless accounts belong to the `email` connection, as an account created by Google
 * belongs to `google`: proven by access to a mailbox, created on first sign-in, without a
 * password. The account is looked for there and only there. An account with a password
 * at the same address, in a pool, is a different account: a mailbox is not a password,
 * and one way of signing in must not quietly become a way into another's accounts.
 *
 * The application must still let its users in by email, as when the message was sent.
 * What follows is the same as after a password: {@see CompleteFirstFactor}, so an
 * account with a second factor gets its challenge — a mailbox is one factor.
 */
final readonly class FinishPasswordlessSignIn
{
    public function __construct(
        private ConnectionAccess $access,
        private ClientRepository $clients,
        private UserRepository $users,
        private LoginStateStore $loginStates,
        private CompleteFirstFactor $completeFirstFactor,
        private RandomSource $random,
        private Clock $clock,
    ) {
    }

    /**
     * @param PasswordlessChallenge $challenge        Already claimed: it signs in once.
     * @param string|null           $currentSessionId The session the browser already holds, if any.
     */
    public function __invoke(
        PasswordlessChallenge $challenge,
        #[\SensitiveParameter] ?string $currentSessionId,
    ): SignedIn|SecondFactorRequired|PasswordlessRefused {
        $client = $challenge->clientId === null ? null : $this->clients->find($challenge->clientId);
        if (! $this->access->allows($client, ConnectionName::email())) {
            return new PasswordlessRefused(PasswordlessFailure::NotAvailable);
        }

        $account = $this->account($challenge->email);
        if (! $account->isActive()) {
            return new PasswordlessRefused(PasswordlessFailure::AccountDisabled);
        }

        // The login page's handle has done its job, as after a password.
        if ($challenge->loginState !== null) {
            $this->loginStates->forget($challenge->loginState);
        }

        return ($this->completeFirstFactor)(
            $account->id,
            [AuthenticationMethod::OneTimePassword],
            ConnectionName::email(),
            LocalPath::orDefault($challenge->nextUrl)->value,
            $challenge->clientId,
            $currentSessionId,
        );
    }

    /**
     * The address's passwordless account, created on first sign-in — its address verified,
     * since the person just proved they read its mail.
     *
     * Matched ignoring case, like the address the person typed: an operator who rewrote an
     * account's address with a capital letter has not made a stranger of its owner. Should
     * two accounts match all the same, the oldest is the one.
     *
     * @param non-empty-string $email
     */
    private function account(string $email): User
    {
        $now = $this->clock->now();
        $user = $this->existing($email);
        if ($user === null) {
            $user = User::registerFromProvider(UserId::generate($this->random), $email, ConnectionName::email(), $now);
            try {
                $this->users->save($user);
            } catch (AlreadyExists $raced) {
                // The same address finishing twice at once: the other request created it.
                return $this->existing($email) ?? throw $raced;
            }

            return $user;
        }

        if ($user->isActive() && ! $user->isEmailVerified()) {
            $user->recordEmailVerification(true, $now);
            $this->users->save($user);
        }

        return $user;
    }

    private function existing(string $email): ?User
    {
        return $this->users->matchingEmail($email, [ConnectionName::email()])[0] ?? null;
    }
}
