<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Authentication\SignIn\HeldSignInRequest;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Application\Authentication\SignIn\SignInRequestExpired;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\AttemptCounter;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Identity\Event\UserSignedUp;
use Clavia\Domain\Identity\PasswordPolicy;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;

/**
 * Create an account from the sign-up page, in the pool the application opens to sign-ups
 * ({@see ConnectionAccess::signUpPool()}).
 *
 * In order: the pool, the password policy, the sign-up limit per client address, and the
 * breached-password check ({@see PasswordScreen}), last because it asks a third party, so the
 * limit bounds how often a client address can make this server ask. Then:
 *
 * - **a pool requiring a verified address** answers {@see CheckYourInbox} whatever happens. A
 *   new account is created unverified and mailed a verification link; an address that already
 *   has one is mailed a notice instead, and the time a password hash would take is spent
 *   either way. Nobody learns from the form whether an address is registered.
 * - **a pool that does not** signs the new account in at once, through
 *   {@see CompleteFirstFactor}, and mails it a verification link all the same. Such a pool
 *   cannot hide a taken address, so it says so ({@see SignUpFailure::AddressTaken}).
 */
final readonly class SignUp
{
    /** The window sign-ups are counted in. */
    public const int WINDOW_SECONDS = 3600;

    /**
     * @param positive-int $limit Sign-ups per hour per client address (`CLAVIA_SIGN_UP_LIMIT`).
     */
    public function __construct(
        private ConnectionAccess $access,
        private ClientRepository $clients,
        private LoginStateStore $loginStates,
        private UserRepository $users,
        private PasswordHasher $hasher,
        private PasswordScreen $passwords,
        private AttemptCounter $counter,
        private SendAccountLink $links,
        private CompleteFirstFactor $completeFirstFactor,
        private TransactionManager $transactions,
        private DomainEvents $events,
        private RandomSource $random,
        private Clock $clock,
        private int $limit,
    ) {
    }

    public function __invoke(
        SignUpRequest $request,
    ): CheckYourInbox|SignedIn|SecondFactorRequired|SignUpRefused|SignInRequestExpired {
        $email = trim($request->email);
        $loginState = $request->loginState === null || $request->loginState === '' ? null : $request->loginState;
        // A request that is gone makes no account: it could only be signed in to nowhere.
        $pending = HeldSignInRequest::find($this->loginStates, $loginState);
        if ($pending instanceof SignInRequestExpired) {
            return $pending;
        }
        $clientId = $pending?->clientId;
        $pool = $this->access->signUpPool($clientId === null ? null : $this->clients->find($clientId));
        if ($pool === null || ($pool->requiresVerifiedEmail && ! $this->access->canSendMail())) {
            return new SignUpRefused(SignUpFailure::NotAvailable, $email);
        }
        if ($email === '' || ! str_contains($email, '@')) {
            return new SignUpRefused(SignUpFailure::InvalidEmail, $email);
        }
        try {
            $password = PasswordPolicy::accept($request->password);
        } catch (InvalidValue) {
            return new SignUpRefused(SignUpFailure::PasswordRejected, $email, PasswordRefusal::Policy);
        }

        $subject = 'sign-up-address:' . $request->clientAddress;
        if ($this->counter->count($subject) >= $this->limit) {
            return new SignUpRefused(SignUpFailure::TooManySignUps, $email);
        }
        $this->counter->increment($subject, self::WINDOW_SECONDS);
        $password = $this->passwords->screen($password);
        if ($password instanceof PasswordRefusal) {
            return new SignUpRefused(SignUpFailure::PasswordRejected, $email, $password);
        }

        // Hashed whether or not an account is made, so the time taken says nothing either.
        $hash = $this->hasher->hash($password);
        $existing = $this->users->findByEmail($pool->name, $email);
        $user = $existing === null ? $this->create($email, $hash, $pool) : null;
        if ($user === null) {
            return $this->taken($existing ?? $this->users->findByEmail($pool->name, $email), $email, $pool, $request);
        }

        $this->links->verification($user, $loginState, $request->clientAddress, $request->language);
        if ($pool->requiresVerifiedEmail) {
            return new CheckYourInbox($email);
        }

        if ($loginState !== null) {
            $this->loginStates->forget($loginState);
        }

        return ($this->completeFirstFactor)(
            $user->id,
            [AuthenticationMethod::Password],
            $pool->name,
            self::nextUrl($pending),
            $clientId,
            $request->currentSessionId,
            $pending?->uiLocales,
        );
    }

    /**
     * The new account, or null when the address turned out to be taken — by a sign-up racing
     * with this one, which the pool's unique constraint settles.
     *
     * @param non-empty-string $hash
     */
    private function create(string $email, #[\SensitiveParameter] string $hash, Connection $pool): ?User
    {
        try {
            $user = User::register(UserId::generate($this->random), $email, $hash, $this->clock->now(), $pool->name);
        } catch (InvalidValue) {
            return null;
        }
        try {
            $this->transactions->transactional(function () use ($user): void {
                $this->users->save($user);
                $this->events->dispatch(new UserSignedUp($user));
            });
        } catch (AlreadyExists) {
            return null;
        }

        return $user;
    }

    private function taken(
        ?User $owner,
        string $email,
        Connection $pool,
        SignUpRequest $request,
    ): CheckYourInbox|SignUpRefused {
        if ($owner === null) {
            // Not taken after all: the address itself could not be an account's.
            return new SignUpRefused(SignUpFailure::InvalidEmail, $email);
        }
        if (! $pool->requiresVerifiedEmail) {
            return new SignUpRefused(SignUpFailure::AddressTaken, $email);
        }
        $this->links->addressTaken($owner->email, $request->clientAddress, $request->language);
        assert($email !== '');

        return new CheckYourInbox($email);
    }

    private static function nextUrl(?LoginState $pending): string
    {
        // Re-validated even though it came from this server's own store.
        return LocalPath::orDefault($pending?->nextUrl)->value;
    }
}
