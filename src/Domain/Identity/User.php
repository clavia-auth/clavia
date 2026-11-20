<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;

/**
 * An end user: a resource owner (RFC 6749 §1.1), and the subject of ID tokens.
 */
final class User
{
    private const int MAX_EMAIL_LENGTH = 320;

    /**
     * @param non-empty-string      $email
     * @param non-empty-string|null $passwordHash
     */
    private function __construct(
        public readonly UserId $id,
        public readonly string $email,
        private ?string $passwordHash,
        private bool $emailVerified,
        private bool $active,
        public readonly DateTimeImmutable $createdAt,
        private DateTimeImmutable $updatedAt,
    ) {
    }

    /**
     * Create an account.
     *
     * @param string      $passwordHash A hash from the password hasher, never a password; null for an
     *                                  account that only ever signs in some other way.
     *
     * @throws InvalidValue When the email address cannot be one.
     */
    public static function register(
        UserId $id,
        string $email,
        #[\SensitiveParameter] ?string $passwordHash,
        DateTimeImmutable $now,
    ): self {
        return new self(
            $id,
            self::email($email),
            $passwordHash === null || $passwordHash === '' ? null : $passwordHash,
            false,
            true,
            $now,
            $now,
        );
    }

    /**
     * Rebuild an account from storage.
     *
     * @throws InvalidValue
     */
    public static function reconstitute(
        UserId $id,
        string $email,
        #[\SensitiveParameter] ?string $passwordHash,
        bool $emailVerified,
        bool $active,
        DateTimeImmutable $createdAt,
        DateTimeImmutable $updatedAt,
    ): self {
        return new self(
            $id,
            self::email($email),
            $passwordHash === null || $passwordHash === '' ? null : $passwordHash,
            $emailVerified,
            $active,
            $createdAt,
            $updatedAt,
        );
    }

    /**
     * Whether the account may still act.
     *
     * Re-checked at every point a token could be minted, not only at login: an account
     * deactivated between authorization and code redemption must not yield a token.
     */
    public function isActive(): bool
    {
        return $this->active;
    }

    public function deactivate(DateTimeImmutable $now): void
    {
        if ($this->active) {
            $this->active = false;
            $this->updatedAt = $now;
        }
    }

    public function activate(DateTimeImmutable $now): void
    {
        if (! $this->active) {
            $this->active = true;
            $this->updatedAt = $now;
        }
    }

    /**
     * The stored password hash, for the hasher to verify against; null when the account
     * has no password at all — which is a failed sign-in, never an empty password
     * matching an empty hash.
     *
     * @return non-empty-string|null
     */
    public function passwordHash(): ?string
    {
        return $this->passwordHash;
    }

    /** Whether the address was confirmed to belong to this person — the OIDC `email_verified` claim. */
    public function isEmailVerified(): bool
    {
        return $this->emailVerified;
    }

    public function updatedAt(): DateTimeImmutable
    {
        return $this->updatedAt;
    }

    /**
     * @return non-empty-string
     *
     * @throws InvalidValue
     */
    private static function email(string $email): string
    {
        $isAddress = $email !== ''
            && strlen($email) <= self::MAX_EMAIL_LENGTH
            && preg_match('/^[^\s@]+@[^\s@]+$/D', $email) === 1;

        if (! $isAddress) {
            throw new InvalidValue(
                'An email address has the form local@domain, with no whitespace, at most 320 bytes.',
            );
        }

        return $email;
    }
}
