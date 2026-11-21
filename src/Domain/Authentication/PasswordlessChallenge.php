<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace Clavia\Domain\Authentication;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;

/**
 * A passwordless sign-in waiting for its proof: the code typed back, or the link followed.
 *
 * Kept server-side under an opaque handle. For a link the handle *is* the secret the
 * email carries; for a code the handle sits in a cookie of the browser that asked, and
 * the challenge keeps only a digest of the code bound to that handle. Binding matters:
 * six digits alone are a million guesses away from any digest of them, but the handle is
 * a 256-bit secret that is never stored — so a dump of the store reveals no code, and a
 * code read in the email answers nothing without the cookie.
 *
 * It carries what finishing needs — the address, where to go afterwards and for which
 * application, the login page's handle to spend — and how many wrong codes it has taken.
 */
final readonly class PasswordlessChallenge
{
    private const int MAX_EMAIL_LENGTH = 320;

    /**
     * @param non-empty-string $email       Normalized by {@see self::address()}.
     * @param Digest|null      $codeDigest  The digest of the code bound to the handle; a code challenge's
     *                                      only, null for a link.
     * @param string           $nextUrl     A local path, already validated by {@see LocalPath}.
     * @param string|null      $loginState  The login page's handle, spent when the sign-in succeeds.
     * @param non-negative-int $attempts    Wrong codes so far.
     *
     * @throws InvalidValue When a code challenge has no code digest, or a link one has one.
     */
    public function __construct(
        public string $email,
        public PasswordlessMode $mode,
        public ?Digest $codeDigest,
        public string $nextUrl,
        public ?ClientId $clientId,
        #[\SensitiveParameter] public ?string $loginState,
        public int $attempts = 0,
    ) {
        if (($mode === PasswordlessMode::Code) !== ($codeDigest !== null)) {
            throw new InvalidValue('A code challenge, and only one, keeps the digest of its code.');
        }
    }

    /**
     * A challenge answered by `$code`, typed into the browser holding `$handle`.
     *
     * @param non-empty-string $email
     * @param non-empty-string $handle
     */
    public static function forCode(
        string $email,
        #[\SensitiveParameter] string $handle,
        OneTimeCode $code,
        string $nextUrl,
        ?ClientId $clientId,
        #[\SensitiveParameter] ?string $loginState,
    ): self {
        return new self(
            $email,
            PasswordlessMode::Code,
            Digest::of(self::bound($handle, $code)),
            $nextUrl,
            $clientId,
            $loginState,
        );
    }

    /**
     * A challenge answered by following a link carrying its handle.
     *
     * @param non-empty-string $email
     */
    public static function forLink(
        string $email,
        string $nextUrl,
        ?ClientId $clientId,
        #[\SensitiveParameter] ?string $loginState,
    ): self {
        return new self($email, PasswordlessMode::Link, null, $nextUrl, $clientId, $loginState);
    }

    /**
     * An address as passwordless sign-in keeps it: trimmed and lower-cased, so the person
     * who typed `Jane@Example.com` once and `jane@example.com` the next time reaches the
     * same account. The local part is case-sensitive in theory and never in practice; an
     * account keyed by a mailbox would otherwise split in two on a capital letter.
     *
     * @return non-empty-string
     *
     * @throws InvalidValue When it cannot be an address: local@domain, no whitespace, at most 320 bytes.
     */
    public static function address(string $typed): string
    {
        $email = mb_check_encoding($typed, 'UTF-8') ? mb_strtolower(trim($typed), 'UTF-8') : '';
        if (
            $email === ''
            || strlen($email) > self::MAX_EMAIL_LENGTH
            || preg_match('/^[^\s@]+@[^\s@]+\.[^\s@]+$/Du', $email) !== 1
        ) {
            throw new InvalidValue('Enter the email address to sign in with.');
        }

        return $email;
    }

    /**
     * Whether `$code`, typed into the browser holding `$handle`, answers this challenge.
     * Constant-time; always false for a link.
     */
    public function acceptsCode(#[\SensitiveParameter] string $handle, OneTimeCode $code): bool
    {
        return $this->codeDigest?->matches(self::bound($handle, $code)) ?? false;
    }

    public function isCode(): bool
    {
        return $this->mode === PasswordlessMode::Code;
    }

    public function isLink(): bool
    {
        return $this->mode === PasswordlessMode::Link;
    }

    /** The code with the handle it answers to: a high-entropy secret, as {@see Digest} requires. */
    private static function bound(#[\SensitiveParameter] string $handle, OneTimeCode $code): string
    {
        return $handle . ':' . $code->value;
    }
}
