<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

use Clavia\Application\Port\AccountLinkStore;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Identity\AccountLinkPurpose;
use Clavia\Domain\Identity\Event\EmailVerified;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;

/**
 * Spend a verification link, from the confirmation page it opened on.
 *
 * Never on the GET that opened it: mail scanners fetch the URLs in an email, and a link spent
 * by a robot would be dead when the person clicks it. Any browser may confirm: opening the
 * mail on another device is what a link is for. Confirming signs nobody in — the link proves
 * the mailbox, not the password.
 */
final readonly class ConfirmEmail
{
    public function __construct(
        private AccountLinkStore $links,
        private UserRepository $users,
        private LoginStateStore $loginStates,
        private TransactionManager $transactions,
        private DomainEvents $events,
        private Clock $clock,
    ) {
    }

    public function __invoke(#[\SensitiveParameter] ?string $token): EmailConfirmed|AccountLinkRefused
    {
        if (
            $token === null
            || $token === ''
            || $this->links->find($token)?->purpose !== AccountLinkPurpose::VerifyEmail
        ) {
            return new AccountLinkRefused();
        }
        // Of two confirmations racing, one claims the link; the other finds it gone.
        $link = $this->links->claim($token);
        $user = $link === null ? null : $this->users->find($link->userId);
        if ($link === null || $user === null || ! $link->stillMatches($user)) {
            return new AccountLinkRefused();
        }

        if (! $user->isEmailVerified()) {
            $this->transactions->transactional(function () use ($user): void {
                $user->recordEmailVerification(true, $this->clock->now());
                $this->users->save($user);
                $this->events->dispatch(new EmailVerified($user->id));
            });
        }

        return new EmailConfirmed($user->email, $this->stillPending($link->loginState));
    }

    /** @return non-empty-string|null */
    private function stillPending(?string $loginState): ?string
    {
        return $loginState !== null && $loginState !== '' && $this->loginStates->get($loginState) !== null
            ? $loginState
            : null;
    }
}
