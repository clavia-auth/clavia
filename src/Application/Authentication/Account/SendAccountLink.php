<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

use Clavia\Application\Authentication\EmailSendLimit;
use Clavia\Application\Port\AccountLinkStore;
use Clavia\Application\Port\Mailer;
use Clavia\Application\Port\MailUnavailable;
use Clavia\Domain\Identity\AccountLink;
use Clavia\Domain\Identity\AccountLinkPurpose;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Mail an account a link — to verify its address, or to choose a password — within the
 * account send limit.
 *
 * The link is opened before the mail goes out, and closed again if the mail cannot leave:
 * nobody would ever hold it. Whether it was sent is the answer; callers that must not say
 * whether an address has an account do not pass it on.
 *
 * A link to choose a password is a reset, or — for an account that has none yet — an
 * invitation: the same link, a different mail.
 */
final readonly class SendAccountLink
{
    /**
     * @param positive-int $verificationLifetimeSeconds `CLAVIA_VERIFICATION_LINK_LIFETIME`.
     * @param positive-int $resetLifetimeSeconds        `CLAVIA_RESET_LINK_LIFETIME`.
     */
    public function __construct(
        private AccountLinkStore $links,
        private EmailSendLimit $sendLimit,
        private Mailer $mailer,
        private AccountMail $mail,
        private SecretGenerator $secrets,
        private int $verificationLifetimeSeconds,
        private int $resetLifetimeSeconds,
    ) {
    }

    /**
     * @param non-empty-string|null $loginState The login page's handle, to return to its request.
     */
    public function verification(User $user, ?string $loginState, string $clientAddress): bool
    {
        return $this->send(AccountLink::verifyEmail($user, $loginState), $clientAddress) === Delivery::Sent;
    }

    /**
     * @param non-empty-string|null $loginState The login page's handle, to return to its request.
     */
    public function reset(User $user, ?string $loginState, string $clientAddress): bool
    {
        return $this->send(AccountLink::resetPassword($user, $loginState), $clientAddress) === Delivery::Sent;
    }

    /**
     * An operator's request: mail the account a link to choose a password, an invitation when
     * it has none, and say how it went.
     *
     * The send limit counts against the address of the operator's request, as the same mail
     * asked for on the public form would.
     */
    public function passwordLink(User $user, string $clientAddress): Delivery
    {
        return $this->send(AccountLink::resetPassword($user, null), $clientAddress, $user->passwordHash() === null);
    }

    /**
     * The notice for an address somebody tried to sign up with again, within the same limit.
     *
     * @param non-empty-string $email
     */
    public function addressTaken(string $email, string $clientAddress): bool
    {
        if (! $this->sendLimit->allowOne(mb_strtolower($email), $clientAddress)) {
            return false;
        }
        try {
            $this->mailer->send($this->mail->addressTaken($email));
        } catch (MailUnavailable) {
            return false;
        }

        return true;
    }

    /**
     * The notice that a second factor was set up on the way to an application requiring one
     * (docs/design/mfa-policies.md §7): best effort, and outside the send limit, since anyone
     * could exhaust that limit with password-reset requests to silence the one signal an
     * owner gets when someone else enrolled first. It follows a completed sign-in, so it
     * cannot be triggered by anyone without the password.
     *
     * @param non-empty-string $email
     */
    public function secondFactorEnrolled(string $email): void
    {
        try {
            $this->mailer->send($this->mail->secondFactorEnrolled($email));
        } catch (MailUnavailable) {
            // No mail backend, or it is down: the enrolment stands, and the audit trail has it.
        }
    }

    private function send(AccountLink $link, string $clientAddress, bool $invitation = false): Delivery
    {
        if (! $this->sendLimit->allowOne(mb_strtolower($link->email), $clientAddress)) {
            return Delivery::LimitReached;
        }
        $token = $this->secrets->token();
        $verifying = $link->purpose === AccountLinkPurpose::VerifyEmail;
        $this->links->open(
            $token,
            $link,
            $verifying ? $this->verificationLifetimeSeconds : $this->resetLifetimeSeconds,
        );
        try {
            $this->mailer->send(match (true) {
                $verifying => $this->mail->verification($link->email, $token),
                $invitation => $this->mail->invitation($link->email, $token),
                default => $this->mail->reset($link->email, $token),
            });
        } catch (MailUnavailable) {
            $this->links->claim($token);

            return Delivery::MailUnavailable;
        }

        return Delivery::Sent;
    }
}
