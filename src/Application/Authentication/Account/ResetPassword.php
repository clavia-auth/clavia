<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Port\AccountLinkStore;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Authentication\Event\SessionEndReason;
use Clavia\Domain\Authentication\Event\SessionsEnded;
use Clavia\Domain\Identity\AccountLinkPurpose;
use Clavia\Domain\Identity\Event\PasswordReset;
use Clavia\Domain\Identity\PasswordPolicy;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;

/**
 * Set a new password from a reset link.
 *
 * The password is checked against the policy before the link is spent, so a refused one
 * leaves the link for another try. Then, with the link claimed and still matching its account
 * (same address, same old password, still active): the password is changed and the address
 * marked verified — the link proved the mailbox — and every session of the account ends. A
 * reset is what a person does when they fear someone else knows their password; whoever that
 * is must not stay signed in, here or, through back-channel logout, anywhere this server
 * signed them in to.
 */
final readonly class ResetPassword
{
    public function __construct(
        private AccountLinkStore $links,
        private UserRepository $users,
        private PasswordHasher $hasher,
        private Sessions $sessions,
        private LoginStateStore $loginStates,
        private TransactionManager $transactions,
        private DomainEvents $events,
        private Clock $clock,
    ) {
    }

    public function __invoke(
        #[\SensitiveParameter] ?string $token,
        #[\SensitiveParameter] string $password,
    ): PasswordChanged|PasswordRejected|AccountLinkRefused {
        if (
            $token === null
            || $token === ''
            || $this->links->find($token)?->purpose !== AccountLinkPurpose::ResetPassword
        ) {
            return new AccountLinkRefused();
        }
        try {
            $accepted = PasswordPolicy::accept($password);
        } catch (InvalidValue $refusal) {
            return new PasswordRejected($refusal->getMessage());
        }

        $link = $this->links->claim($token);
        $user = $link === null ? null : $this->users->find($link->userId);
        if ($link === null || $user === null || ! $link->stillMatches($user)) {
            return new AccountLinkRefused();
        }

        $hash = $this->hasher->hash($accepted);
        $this->transactions->transactional(function () use ($user, $hash): void {
            $now = $this->clock->now();
            $user->changePassword($hash, $now);
            $user->recordEmailVerification(true, $now);
            $this->users->save($user);
            $this->events->dispatch(new PasswordReset($user->id));
        });
        $ended = $this->sessions->endEverywhere($user->id);
        $this->events->dispatch(new SessionsEnded(SessionEndReason::PasswordReset, $ended));

        $loginState = $link->loginState;

        return new PasswordChanged(
            $user->email,
            $loginState !== null && $this->loginStates->get($loginState) !== null ? $loginState : null,
        );
    }
}
