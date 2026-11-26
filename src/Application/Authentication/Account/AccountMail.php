<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

use Clavia\Application\Port\MailContent;
use Clavia\Application\Port\MailKind;
use Clavia\Application\Port\OutgoingMail;
use Clavia\Domain\Shared\Language;

/**
 * The account emails: the verification link, the reset link, the invitation an operator sends, the
 * notice sent to an address somebody tried to sign up with again, and the one that a second factor was
 * set up. What each carries, in the language it is for; their words are the catalogue's
 * (`mail.*` in `translations/`, docs/design/translated-sign-in-pages.md §4).
 *
 * Plain text, short, and saying what the link is good for and for how long. Each ends by telling
 * someone who did not ask that ignoring it is safe — which it is: a link does nothing until it is
 * followed and confirmed.
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
    public function verification(string $email, #[\SensitiveParameter] string $token, Language $language): OutgoingMail
    {
        return $this->mail($email, $language, MailKind::Verification, [
            'link' => $this->url(self::VERIFY_PATH, $token),
        ], $this->verificationLifetimeSeconds);
    }

    /**
     * @param non-empty-string $email
     * @param non-empty-string $token The link's secret.
     */
    public function reset(string $email, #[\SensitiveParameter] string $token, Language $language): OutgoingMail
    {
        return $this->mail($email, $language, MailKind::Reset, [
            'link' => $this->url(self::RESET_PATH, $token),
        ], $this->resetLifetimeSeconds);
    }

    /**
     * What a person gets when an operator creates their account without a password: the same
     * link as a reset, worded for someone who has never signed in.
     *
     * @param non-empty-string $email
     * @param non-empty-string $token The link's secret.
     */
    public function invitation(string $email, #[\SensitiveParameter] string $token, Language $language): OutgoingMail
    {
        return $this->mail($email, $language, MailKind::Invitation, [
            'link' => $this->url(self::RESET_PATH, $token),
        ], $this->resetLifetimeSeconds);
    }

    /**
     * The notice for an address that already has an account: no link that changes anything, only the
     * way to a reset the owner asks for themselves.
     *
     * @param non-empty-string $email
     */
    public function addressTaken(string $email, Language $language): OutgoingMail
    {
        return $this->mail($email, $language, MailKind::AddressTaken, [
            'link' => rtrim($this->issuer, '/') . self::FORGOT_PATH,
        ]);
    }

    /**
     * The notice that a second factor was set up on the way to an application: if it was not the
     * owner, someone knows the password, and a reset signs every session out.
     *
     * @param non-empty-string $email
     */
    public function secondFactorEnrolled(string $email, Language $language): OutgoingMail
    {
        return $this->mail($email, $language, MailKind::SecondFactorEnrolled, [
            'link' => rtrim($this->issuer, '/') . self::FORGOT_PATH,
        ]);
    }

    /**
     * @param non-empty-string $path
     * @param non-empty-string $token
     */
    public function url(string $path, #[\SensitiveParameter] string $token): string
    {
        return rtrim($this->issuer, '/') . $path . '?'
            . http_build_query(['token' => $token], '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * @param non-empty-string                $email
     * @param array<non-empty-string, string> $values
     * @param positive-int|null               $lifetimeSeconds
     */
    private function mail(
        string $email,
        Language $language,
        MailKind $kind,
        #[\SensitiveParameter] array $values,
        ?int $lifetimeSeconds = null,
    ): OutgoingMail {
        return new OutgoingMail(
            $email,
            new MailContent($kind, ['site' => $this->site, ...$values], $lifetimeSeconds),
            $language,
        );
    }
}
