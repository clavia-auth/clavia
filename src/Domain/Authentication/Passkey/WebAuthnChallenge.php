<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Passkey;

use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use DateTimeImmutable;

/**
 * A WebAuthn ceremony in progress: the challenge the browser will sign, what it is for, and
 * what it is bound to (WebAuthn Level 3 §13.4.3: a challenge is random, at least sixteen
 * bytes, and used once).
 *
 * Thirty-two random bytes. It is bound to its purpose, and to its context: the account for a
 * registration and a second factor, the login state for a sign-in, so a response answers this
 * authorization request and no other. The login state and the second-factor challenge are
 * handles a browser holds, so only their digest is kept here.
 *
 * It is kept behind a handle the browser holds, and claimed before it is checked, so it is spent
 * whether the response is good or bad.
 */
final readonly class WebAuthnChallenge
{
    public const int LENGTH = 32;

    private function __construct(
        public string $challenge,
        public WebAuthnPurpose $purpose,
        public ?UserId $userId,
        public ?Digest $context,
        public DateTimeImmutable $expiresAt,
    ) {
    }

    /** To register a passkey on `$userId`'s account. */
    public static function forRegistration(
        RandomSource $random,
        UserId $userId,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
    ): self {
        return new self(
            $random->bytes(self::LENGTH),
            WebAuthnPurpose::Registration,
            $userId,
            null,
            self::expiry($now, $lifetimeSeconds),
        );
    }

    /**
     * To sign in with a passkey, answering the authorization request held behind `$loginState`.
     *
     * @param non-empty-string $loginState The login state's handle, kept as its digest.
     */
    public static function forSignIn(
        RandomSource $random,
        #[\SensitiveParameter] string $loginState,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
    ): self {
        return new self(
            $random->bytes(self::LENGTH),
            WebAuthnPurpose::SignIn,
            null,
            Digest::of($loginState),
            self::expiry($now, $lifetimeSeconds),
        );
    }

    /**
     * To complete the sign-in of `$userId` with a passkey, answering the second-factor challenge
     * behind `$mfaChallenge`.
     *
     * @param non-empty-string $mfaChallenge The second-factor challenge's handle, kept as its digest.
     */
    public static function forSecondFactor(
        RandomSource $random,
        UserId $userId,
        #[\SensitiveParameter] string $mfaChallenge,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
    ): self {
        return new self(
            $random->bytes(self::LENGTH),
            WebAuthnPurpose::SecondFactor,
            $userId,
            Digest::of($mfaChallenge),
            self::expiry($now, $lifetimeSeconds),
        );
    }

    /**
     * A challenge read back from storage.
     *
     * @throws InvalidValue When it is not thirty-two bytes, or what its purpose binds it to is
     *                      missing: a registration or second factor with no account, a sign-in or
     *                      second factor with no context.
     */
    public static function reconstitute(
        string $challenge,
        WebAuthnPurpose $purpose,
        ?UserId $userId,
        ?Digest $context,
        DateTimeImmutable $expiresAt,
    ): self {
        $accountless = $purpose === WebAuthnPurpose::SignIn;
        $contextless = $purpose === WebAuthnPurpose::Registration;
        if (
            strlen($challenge) !== self::LENGTH
            || ($userId === null) !== $accountless
            || ($context === null) !== $contextless
        ) {
            throw new InvalidValue('That is not a WebAuthn challenge.');
        }

        return new self($challenge, $purpose, $userId, $context, $expiresAt);
    }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }

    /**
     * Whether it was made for `$purpose` and bound to `$context` (a login state or a
     * second-factor challenge handle; none for a registration).
     */
    public function isFor(WebAuthnPurpose $purpose, #[\SensitiveParameter] ?string $context = null): bool
    {
        return $this->purpose === $purpose
            && ($this->context === null ? $context === null : $context !== null && $this->context->matches($context));
    }

    /** The form the browser exchanges: unpadded base64url. */
    public function toBase64Url(): string
    {
        return Base64Url::encode($this->challenge);
    }

    private static function expiry(DateTimeImmutable $now, int $lifetimeSeconds): DateTimeImmutable
    {
        if ($lifetimeSeconds < 1) {
            throw new InvalidValue('A ceremony lives for at least a second.');
        }

        return $now->modify(sprintf('+%d seconds', $lifetimeSeconds));
    }
}
