<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;

/**
 * An end user: a resource owner (RFC 6749 §1.1), and the subject of ID tokens.
 *
 * Every account belongs to exactly one connection, for good: the pool it was created in,
 * or the external connection that created it. The same address may exist in two pools
 * as two accounts — a customer and an employee — so an address names an account only
 * within its connection.
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
        public private(set) string $email,
        private ?string $passwordHash,
        private bool $emailVerified,
        private bool $active,
        private Profile $profile,
        public readonly DateTimeImmutable $createdAt,
        private DateTimeImmutable $updatedAt,
        public readonly ConnectionName $connection,
        private AppMetadata $appMetadata,
    ) {
    }

    /**
     * Create an account.
     *
     * @param string              $passwordHash A hash from the password hasher, never a password; null
     *                                          for an account that only ever signs in some other way.
     * @param ConnectionName|null $pool         The database connection it belongs to; null for the
     *                                          default pool.
     *
     * @throws InvalidValue When the email address cannot be one.
     */
    public static function register(
        UserId $id,
        string $email,
        #[\SensitiveParameter] ?string $passwordHash,
        DateTimeImmutable $now,
        ?ConnectionName $pool = null,
    ): self {
        return new self(
            $id,
            self::email($email),
            $passwordHash === null || $passwordHash === '' ? null : $passwordHash,
            false,
            true,
            Profile::empty(),
            $now,
            $now,
            $pool ?? ConnectionName::defaultPool(),
            AppMetadata::empty(),
        );
    }

    /**
     * Create an account for a person whose address something vouched for — an external
     * provider reporting it as verified, or a code or link sent to it coming back: no
     * password, the address verified — an account is never created from an address nothing
     * vouches for — and belonging to the connection that signed them in.
     *
     * @throws InvalidValue When the email address cannot be one.
     */
    public static function registerFromProvider(
        UserId $id,
        string $verifiedEmail,
        ConnectionName $connection,
        DateTimeImmutable $now,
    ): self {
        return new self(
            $id,
            self::email($verifiedEmail),
            null,
            true,
            true,
            Profile::empty(),
            $now,
            $now,
            $connection,
            AppMetadata::empty(),
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
        Profile $profile,
        DateTimeImmutable $createdAt,
        DateTimeImmutable $updatedAt,
        ConnectionName $connection,
        ?AppMetadata $appMetadata = null,
    ): self {
        return new self(
            $id,
            self::email($email),
            $passwordHash === null || $passwordHash === '' ? null : $passwordHash,
            $emailVerified,
            $active,
            $profile,
            $createdAt,
            $updatedAt,
            $connection,
            $appMetadata ?? AppMetadata::empty(),
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

    /**
     * Move the account to another address. A new address has proven nothing yet, so it
     * is unverified until something proves it; the same address changes nothing.
     *
     * @throws InvalidValue When the address cannot be one.
     */
    public function changeEmail(string $email, DateTimeImmutable $now): void
    {
        $email = self::email($email);
        if ($email !== $this->email) {
            $this->email = $email;
            $this->emailVerified = false;
            $this->updatedAt = $now;
        }
    }

    /**
     * Record whether the address is confirmed to belong to this person — by whatever
     * proved it: an operator, a verification link, a provider's verified claim.
     */
    public function recordEmailVerification(bool $verified, DateTimeImmutable $now): void
    {
        if ($verified !== $this->emailVerified) {
            $this->emailVerified = $verified;
            $this->updatedAt = $now;
        }
    }

    /**
     * Replace the password.
     *
     * @param non-empty-string $passwordHash A hash from the password hasher, never a password.
     */
    public function changePassword(#[\SensitiveParameter] string $passwordHash, DateTimeImmutable $now): void
    {
        $this->passwordHash = $passwordHash;
        $this->updatedAt = $now;
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

    /** What the person is called and how they present themselves: the `profile` scope's claims. */
    public function profile(): Profile
    {
        return $this->profile;
    }

    /**
     * Replace the profile as a whole. A change moves `updatedAt`, which relying parties
     * read as the `updated_at` claim to know their copy is stale.
     */
    public function changeProfile(Profile $profile, DateTimeImmutable $now): void
    {
        if (! $profile->equals($this->profile)) {
            $this->profile = $profile;
            $this->updatedAt = $now;
        }
    }

    /** What operators keep about the account ({@see AppMetadata}); `{}` when nothing. */
    public function appMetadata(): AppMetadata
    {
        return $this->appMetadata;
    }

    /**
     * Replace the application metadata as a whole: what is given is what is kept, and a key is
     * removed by leaving it out. Only an operator's change reaches this (docs/design/custom-claims.md
     * §5.1).
     */
    public function changeAppMetadata(AppMetadata $metadata, DateTimeImmutable $now): void
    {
        if (! $metadata->equals($this->appMetadata)) {
            $this->appMetadata = $metadata;
            $this->updatedAt = $now;
        }
    }

    /** When anything about the account last changed — the OIDC `updated_at` claim. */
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
