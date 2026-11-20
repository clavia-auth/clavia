<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\Shared\Digest;
use DateTimeImmutable;

/**
 * Access tokens kept in an array.
 */
final class InMemoryAccessTokenRepository implements AccessTokenRepository
{
    /** @var array<string, AccessToken> Keyed by digest. */
    private array $tokens = [];

    #[\Override]
    public function add(AccessToken $token): void
    {
        $this->tokens[$token->digest->toString()] = $token;
    }

    #[\Override]
    public function findByDigest(Digest $digest): ?AccessToken
    {
        return $this->tokens[$digest->toString()] ?? null;
    }

    #[\Override]
    public function revokeIssuedFrom(AuthorizationCodeId $code, DateTimeImmutable $now): int
    {
        $revoked = 0;

        foreach ($this->tokens as $key => $token) {
            $fromThisCode = $token->authorizationCodeId !== null && $token->authorizationCodeId->equals($code);
            if (! $fromThisCode || $token->isRevoked()) {
                continue;
            }

            $this->tokens[$key] = AccessToken::reconstitute(
                $token->id,
                $token->digest,
                $token->clientId,
                $token->userId,
                $token->authorizationCodeId,
                $token->scope,
                $token->issuedAt,
                $token->expiresAt,
                $now,
            );
            $revoked++;
        }

        return $revoked;
    }

    /**
     * @return list<AccessToken> Everything stored, for assertions.
     */
    public function all(): array
    {
        return array_values($this->tokens);
    }
}
