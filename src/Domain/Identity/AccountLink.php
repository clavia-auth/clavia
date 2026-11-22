<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

use Clavia\Domain\Shared\Digest;

/**
 * What a link emailed to an account stands for, while it waits to be followed: verify the
 * address, or set a new password.
 *
 * The link itself is a secret token kept only as its digest; this is what the token unlocks.
 * It answers for one account, at one address, and — for a reset — against one password: the
 * moment any of those changes, the link is dead ({@see stillMatches()}). So a reset link
 * mailed before a password change cannot undo it, and a verification link sent to a
 * previous address cannot verify the new one.
 */
final readonly class AccountLink
{
    /**
     * @param non-empty-string      $email               The address the link was sent to.
     * @param non-empty-string|null $loginState          The login page's handle it came from, to
     *                                                   return to that authorization request.
     * @param Digest|null           $passwordFingerprint For a reset: the digest of the password hash
     *                                                   it was issued against ("none" for no password).
     */
    private function __construct(
        public AccountLinkPurpose $purpose,
        public UserId $userId,
        public string $email,
        public ?string $loginState,
        public ?Digest $passwordFingerprint,
    ) {
    }

    /**
     * A link proving `$user` controls their current address.
     *
     * @param non-empty-string|null $loginState
     */
    public static function verifyEmail(User $user, ?string $loginState): self
    {
        return new self(AccountLinkPurpose::VerifyEmail, $user->id, $user->email, $loginState, null);
    }

    /**
     * A link letting `$user` set a new password, valid until their password changes.
     *
     * @param non-empty-string|null $loginState
     */
    public static function resetPassword(User $user, ?string $loginState): self
    {
        return new self(
            AccountLinkPurpose::ResetPassword,
            $user->id,
            $user->email,
            $loginState,
            self::fingerprint($user),
        );
    }

    /**
     * A link read back from storage.
     *
     * @param non-empty-string      $email
     * @param non-empty-string|null $loginState
     */
    public static function reconstitute(
        AccountLinkPurpose $purpose,
        UserId $userId,
        string $email,
        ?string $loginState,
        ?Digest $passwordFingerprint,
    ): self {
        return new self($purpose, $userId, $email, $loginState, $passwordFingerprint);
    }

    /**
     * Whether the link still answers for `$user` as they are now: the same account, active,
     * at the address the link was sent to, and — for a reset — with the password it was
     * issued against.
     */
    public function stillMatches(User $user): bool
    {
        if (! $user->id->equals($this->userId) || ! $user->isActive()) {
            return false;
        }
        if (mb_strtolower($user->email) !== mb_strtolower($this->email)) {
            return false;
        }

        return $this->purpose !== AccountLinkPurpose::ResetPassword
            || ($this->passwordFingerprint !== null && $this->passwordFingerprint->equals(self::fingerprint($user)));
    }

    /**
     * The digest of the account's password hash: changes whenever the password does, and
     * gives nothing of the hash away.
     */
    private static function fingerprint(User $user): Digest
    {
        return Digest::of('password:' . ($user->passwordHash() ?? ''));
    }
}
