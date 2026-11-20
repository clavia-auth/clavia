<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\RefreshToken;
use Clavia\Domain\OAuth2\RefreshTokenId;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Clavia\Domain\Shared\Digest;
use DateTimeImmutable;
use LogicException;

/**
 * Refresh tokens kept in an array. Revoking rebuilds the token, as reading it back from
 * storage would.
 */
final class InMemoryRefreshTokenRepository implements RefreshTokenRepository
{
    /** @var array<string, RefreshToken> Keyed by digest. */
    private array $tokens = [];

    /**
     * @param InMemoryTransactionManager|null $transactions When given, locking outside one is refused, as
     *                                                      PostgreSQL's adapter refuses it.
     */
    public function __construct(private readonly ?InMemoryTransactionManager $transactions = null)
    {
    }

    #[\Override]
    public function add(RefreshToken $token): void
    {
        $this->tokens[$token->digest->toString()] = clone $token;
    }

    #[\Override]
    public function findByDigest(Digest $digest): ?RefreshToken
    {
        $token = $this->tokens[$digest->toString()] ?? null;

        return $token === null ? null : clone $token;
    }

    #[\Override]
    public function lockForRefresh(Digest $digest): ?RefreshToken
    {
        if ($this->transactions !== null && ! $this->transactions->isActive()) {
            throw new LogicException('A refresh token can only be locked inside a transaction.');
        }

        return $this->findByDigest($digest);
    }

    #[\Override]
    public function save(RefreshToken $token): void
    {
        $this->tokens[$token->digest->toString()] = clone $token;
    }

    #[\Override]
    public function revokeFamily(RefreshTokenId $family, DateTimeImmutable $now): int
    {
        return $this->revokeWhere(static fn (RefreshToken $token): bool => $token->familyId->equals($family), $now);
    }

    #[\Override]
    public function revokeIssuedFrom(AuthorizationCodeId $code, DateTimeImmutable $now): int
    {
        return $this->revokeWhere(
            static fn (RefreshToken $token): bool => $token->authorizationCodeId?->equals($code) === true,
            $now,
        );
    }

    /**
     * @return list<RefreshToken> Everything stored, for assertions.
     */
    public function all(): array
    {
        return array_values(array_map(static fn (RefreshToken $token): RefreshToken => clone $token, $this->tokens));
    }

    /**
     * @param callable(RefreshToken): bool $matches
     */
    private function revokeWhere(callable $matches, DateTimeImmutable $now): int
    {
        $revoked = 0;
        foreach ($this->tokens as $key => $token) {
            if (! $matches($token) || $token->revokedAt() !== null) {
                continue;
            }
            $this->tokens[$key] = RefreshToken::reconstitute(
                $token->id,
                $token->digest,
                $token->familyId,
                $token->clientId,
                $token->userId,
                $token->authorizationCodeId,
                $token->scope,
                $token->audience,
                $token->issuedAt,
                $token->expiresAt,
                $token->familyExpiresAt,
                $token->usedAt(),
                $now,
            );
            $revoked++;
        }

        return $revoked;
    }
}
