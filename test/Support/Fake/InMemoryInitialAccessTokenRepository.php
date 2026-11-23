<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Client\Registration\InitialAccessToken;
use Clavia\Domain\Client\Registration\InitialAccessTokenId;
use Clavia\Domain\Client\Registration\InitialAccessTokenRepository;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use DateTimeImmutable;

/**
 * Initial access tokens in memory. The tokens are immutable, so storing them is copying them.
 */
final class InMemoryInitialAccessTokenRepository implements InitialAccessTokenRepository
{
    /** @var array<string, InitialAccessToken> By id. */
    private array $tokens = [];

    #[\Override]
    public function add(InitialAccessToken $token): void
    {
        $this->tokens[$token->id->value] = $token;
    }

    #[\Override]
    public function find(InitialAccessTokenId $id): ?InitialAccessToken
    {
        return $this->tokens[$id->value] ?? null;
    }

    #[\Override]
    public function save(InitialAccessToken $token): void
    {
        $stored = $this->tokens[$token->id->value] ?? null;
        if ($stored !== null) {
            // As in storage: only the revocation is written; the uses stay what they are.
            $this->tokens[$token->id->value] = $token->revokedAt === null
                ? $stored
                : $stored->revoke($token->revokedAt);
        }
    }

    #[\Override]
    public function page(PageRequest $request): Page
    {
        return InMemoryPaging::page(
            array_values($this->tokens),
            $request,
            static fn (InitialAccessToken $token): array => [$token->description],
            static fn (InitialAccessToken $token): array => [$token->createdAt, $token->id->value],
        );
    }

    #[\Override]
    public function spendOne(Digest $digest, DateTimeImmutable $now): ?InitialAccessTokenId
    {
        foreach ($this->tokens as $key => $token) {
            if ($token->digest->equals($digest) && $token->isUsableAt($now)) {
                $this->tokens[$key] = InitialAccessToken::reconstitute(
                    $token->id,
                    $token->digest,
                    $token->description,
                    $token->createdAt,
                    $token->expiresAt,
                    $token->maxUses,
                    $token->uses + 1,
                    $token->revokedAt,
                );

                return $token->id;
            }
        }

        return null;
    }
}
