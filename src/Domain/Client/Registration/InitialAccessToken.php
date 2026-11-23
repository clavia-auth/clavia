<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client\Registration;

use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;

/**
 * What lets software register itself as a client (RFC 7591 §1.2, §3): a secret an operator hands
 * out, good for a number of registrations until a date, revocable at any time
 * (docs/design/dynamic-client-registration.md §2).
 *
 * It does one thing — register third-party clients — so it is no access token for the Management
 * API, whose `create:clients` would reach the operator's own applications too. The secret is
 * handed out once and stored as its digest; uses are spent in storage, by a conditional write
 * ({@see InitialAccessTokenRepository::spendOne()}), so two registrations never share the last.
 */
final readonly class InitialAccessToken
{
    public const int MAX_DESCRIPTION_LENGTH = 120;
    public const int MAX_USES = 1000;
    public const int MIN_LIFETIME_SECONDS = 60;
    /** Ninety days: a token is for a partner's setup, not a standing credential. */
    public const int MAX_LIFETIME_SECONDS = 7_776_000;

    /**
     * @param non-empty-string $description
     * @param positive-int     $maxUses
     * @param int<0, max>      $uses
     */
    private function __construct(
        public InitialAccessTokenId $id,
        public Digest $digest,
        public string $description,
        public DateTimeImmutable $createdAt,
        public DateTimeImmutable $expiresAt,
        public int $maxUses,
        public int $uses,
        public ?DateTimeImmutable $revokedAt,
    ) {
    }

    /**
     * A new token, with none of its uses spent.
     *
     * @param Digest $digest The digest of the secret handed out; the secret itself is never kept.
     *
     * @throws InvalidValue When the description, the lifetime or the number of uses is out of bounds.
     */
    public static function issue(
        InitialAccessTokenId $id,
        Digest $digest,
        string $description,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
        int $maxUses,
    ): self {
        if ($lifetimeSeconds < self::MIN_LIFETIME_SECONDS || $lifetimeSeconds > self::MAX_LIFETIME_SECONDS) {
            throw new InvalidValue('An initial access token lives between a minute and ninety days.');
        }

        return self::reconstitute(
            $id,
            $digest,
            $description,
            $now,
            $now->modify(sprintf('+%d seconds', $lifetimeSeconds)),
            $maxUses,
            0,
            null,
        );
    }

    /**
     * A token as storage holds it. The same rules apply, so a token that exists is coherent.
     *
     * @throws InvalidValue
     */
    public static function reconstitute(
        InitialAccessTokenId $id,
        Digest $digest,
        string $description,
        DateTimeImmutable $createdAt,
        DateTimeImmutable $expiresAt,
        int $maxUses,
        int $uses,
        ?DateTimeImmutable $revokedAt,
    ): self {
        if (
            $description === ''
            || strlen($description) > self::MAX_DESCRIPTION_LENGTH
            || preg_match('/[\x00-\x1F\x7F]/', $description) === 1
        ) {
            throw new InvalidValue('A description is 1 to 120 bytes, without control characters.');
        }
        if ($maxUses < 1 || $maxUses > self::MAX_USES) {
            throw new InvalidValue('An initial access token registers between 1 and 1000 clients.');
        }
        if ($uses < 0 || $uses > $maxUses) {
            throw new InvalidValue('An initial access token cannot be used more than it allows.');
        }
        if ($expiresAt <= $createdAt) {
            throw new InvalidValue('An initial access token expires after it was issued.');
        }

        return new self($id, $digest, $description, $createdAt, $expiresAt, $maxUses, $uses, $revokedAt);
    }

    /** Whether it would register a client now: not revoked, not expired, a use left. */
    public function isUsableAt(DateTimeImmutable $now): bool
    {
        return $this->stateAt($now) === InitialAccessTokenState::Active;
    }

    /** Revoked first, then expired, then used up: what stops it, in the order an operator acts on. */
    public function stateAt(DateTimeImmutable $now): InitialAccessTokenState
    {
        return match (true) {
            $this->revokedAt !== null => InitialAccessTokenState::Revoked,
            $now >= $this->expiresAt => InitialAccessTokenState::Expired,
            $this->uses >= $this->maxUses => InitialAccessTokenState::UsedUp,
            default => InitialAccessTokenState::Active,
        };
    }

    /**
     * The token, stopped at once. Clients it registered keep working. Revoking it twice keeps the
     * first instant.
     */
    public function revoke(DateTimeImmutable $now): self
    {
        return $this->revokedAt !== null ? $this : clone($this, ['revokedAt' => $now]);
    }
}
