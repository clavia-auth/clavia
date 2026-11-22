<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Application\Authentication\Account\Delivery;
use Clavia\Application\Authentication\Account\SendAccountLink;
use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\Mailer;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\Event\PasswordLinkSent as PasswordLinkSentEvent;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `POST /api/v1/users/{user_id}/password-reset`: mail an account the link to choose a
 * password — an invitation when it has none yet, a reset when it has one.
 *
 * It is the link the sign-in page mails to whoever asks ({@see SendAccountLink}), at an
 * operator's request: opened against the account as it is now, so choosing a password, or
 * changing the address, kills it. Unlike the public form, the caller is authenticated and
 * is told how it went. Only an account in a pool can hold a password; an external
 * connection's accounts sign in through their provider. A deactivated account cannot use a
 * link, so it is refused rather than mailed one that would not work.
 */
final readonly class SendPasswordLink
{
    public function __construct(
        private UserRepository $users,
        private ConnectionRepository $connections,
        private SendAccountLink $links,
        private Mailer $mailer,
        private DomainEvents $events,
    ) {
    }

    /**
     * @param string $clientAddress The address of the operator's request (`REMOTE_ADDR`), which
     *                              the send limit counts as it does on the public form.
     *
     * @throws NotFound     When there is no such account.
     * @throws InvalidValue When the account is not in a pool, so it has no password to choose.
     * @throws Conflict     When the account is deactivated.
     */
    public function __invoke(UserId $id, string $clientAddress): PasswordLinkSent|PasswordLinkRefused
    {
        $user = $this->users->find($id) ?? throw NotFound::of('user');
        if (! ($this->connections->find($user->connection)?->isDatabase() ?? false)) {
            throw new InvalidValue(sprintf(
                "Only an account in a pool has a password; '%s' is not a pool.",
                $user->connection->value,
            ));
        }
        if (! $user->isActive()) {
            throw new Conflict('A deactivated account cannot choose a password.');
        }
        if (! $this->mailer->canSend()) {
            return PasswordLinkRefused::MailUnavailable;
        }

        $invitation = $user->passwordHash() === null;

        return match ($this->links->passwordLink($user, $clientAddress)) {
            Delivery::Sent => $this->sent($user->id, $invitation),
            Delivery::LimitReached => PasswordLinkRefused::LimitReached,
            Delivery::MailUnavailable => PasswordLinkRefused::MailUnavailable,
        };
    }

    private function sent(UserId $id, bool $invitation): PasswordLinkSent
    {
        $this->events->dispatch(new PasswordLinkSentEvent($id, $invitation));

        return new PasswordLinkSent($invitation);
    }
}
