<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

use Clavia\Application\Port\OutgoingMail;

/**
 * The words of the account emails: the verification link, the reset link, the invitation
 * an operator sends, and the notice sent to an address somebody tried to sign up with again.
 *
 * Plain text, short, and saying what the link is good for and for how long. Each ends by
 * telling someone who did not ask that ignoring it is safe — which it is: a link does
 * nothing until it is followed and confirmed.
 */
final readonly class AccountMail
{
    /** Where a verification link leads: a confirmation page, never a change on GET. */
    public const string VERIFY_PATH = '/auth/verify-email';

    /** Where a reset link leads: the new-password form. */
    public const string RESET_PATH = '/auth/password/reset';

    /** Where the taken-address notice sends the owner. */
    private const string FORGOT_PATH = '/auth/password/forgot';

    /**
     * @param non-empty-string $site                      What the person knows this server as: the root domain.
     * @param non-empty-string $issuer                    The base URL links are built on.
     * @param positive-int     $verificationLifetimeSeconds
     * @param positive-int     $resetLifetimeSeconds
     */
    public function __construct(
        private string $site,
        private string $issuer,
        private int $verificationLifetimeSeconds,
        private int $resetLifetimeSeconds,
    ) {
    }

    /**
     * @param non-empty-string $email
     * @param non-empty-string $token The link's secret.
     */
    public function verification(string $email, #[\SensitiveParameter] string $token): OutgoingMail
    {
        return new OutgoingMail(
            $email,
            sprintf('Confirm your email address for %s', $this->site),
            sprintf(
                "Open this link to confirm that this address is yours:\n\n%s\n\n"
                . "It works once and expires in %s.\n\n"
                . "If you did not create an account, ignore this email.\n",
                $this->url(self::VERIFY_PATH, $token),
                self::duration($this->verificationLifetimeSeconds),
            ),
        );
    }

    /**
     * @param non-empty-string $email
     * @param non-empty-string $token The link's secret.
     */
    public function reset(string $email, #[\SensitiveParameter] string $token): OutgoingMail
    {
        return new OutgoingMail(
            $email,
            sprintf('Choose a new password for %s', $this->site),
            sprintf(
                "Open this link to choose a new password:\n\n%s\n\n"
                . "It works once and expires in %s. Choosing a new password signs you out everywhere.\n\n"
                . "If you did not ask for this, ignore this email: your password stays as it is.\n",
                $this->url(self::RESET_PATH, $token),
                self::duration($this->resetLifetimeSeconds),
            ),
        );
    }

    /**
     * What a person gets when an operator creates their account without a password: the same
     * link as a reset, worded for someone who has never signed in.
     *
     * @param non-empty-string $email
     * @param non-empty-string $token The link's secret.
     */
    public function invitation(string $email, #[\SensitiveParameter] string $token): OutgoingMail
    {
        return new OutgoingMail(
            $email,
            sprintf('You have been invited to %s', $this->site),
            sprintf(
                "An account has been created for you on %s. Open this link to choose its password:\n\n%s\n\n"
                . "It works once and expires in %s.\n\n"
                . "If you were not expecting this, ignore this email: no one can sign in to the account without it.\n",
                $this->site,
                $this->url(self::RESET_PATH, $token),
                self::duration($this->resetLifetimeSeconds),
            ),
        );
    }

    /**
     * What the owner of an address gets when somebody tries to create an account with it
     * again: no link, nothing to spend, only where to go if it was them.
     *
     * @param non-empty-string $email
     */
    public function addressTaken(string $email): OutgoingMail
    {
        return new OutgoingMail(
            $email,
            sprintf('You already have an account on %s', $this->site),
            sprintf(
                "Someone tried to create an account on %s with this address, which already has one.\n\n"
                . "If it was you, sign in instead. If you have forgotten your password, choose a new one here:\n\n"
                . "%s\n\n"
                . "If it was not you, ignore this email: nothing has changed.\n",
                $this->site,
                rtrim($this->issuer, '/') . self::FORGOT_PATH,
            ),
        );
    }

    /**
     * @param non-empty-string $token
     */
    public function url(string $path, #[\SensitiveParameter] string $token): string
    {
        return rtrim($this->issuer, '/') . $path . '?'
            . http_build_query(['token' => $token], '', '&', PHP_QUERY_RFC3986);
    }

    /** Whole minutes, or hours from two hours on, rounded up. */
    private static function duration(int $seconds): string
    {
        if ($seconds >= 7200) {
            $hours = intdiv($seconds + 3599, 3600);

            return $hours . ' hours';
        }
        $minutes = intdiv($seconds + 59, 60);

        return $minutes === 1 ? '1 minute' : $minutes . ' minutes';
    }
}
