<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Contract\AccessTokenRepositoryContract;
use ClaviaTest\Support\Contract\RefreshTokenRepositoryContract;
use ClaviaTest\Support\Fake\InMemoryAccessTokenRepository;
use ClaviaTest\Support\Fake\InMemoryRefreshTokenRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/**
 * The in-memory access and refresh token repositories against their contracts.
 */
final class InMemoryAccessTokenRepositoryTest extends TestCase
{
    use AccessTokenRepositoryContract;
    use RefreshTokenRepositoryContract;

    private InMemoryAccessTokenRepository $tokens;
    private InMemoryTransactionManager $transactions;
    private InMemoryRefreshTokenRepository $refreshTokens;

    #[\Override]
    protected function setUp(): void
    {
        $this->tokens = new InMemoryAccessTokenRepository();
        $this->transactions = new InMemoryTransactionManager();
        $this->refreshTokens = new InMemoryRefreshTokenRepository($this->transactions);
    }

    #[\Override]
    protected function tokens(): AccessTokenRepository
    {
        return $this->tokens;
    }

    #[\Override]
    protected function refreshTokens(): RefreshTokenRepository
    {
        return $this->refreshTokens;
    }

    #[\Override]
    protected function transactional(callable $work): mixed
    {
        return $this->transactions->transactional($work);
    }

    #[\Override]
    protected function aStoredCode(string $value): AuthorizationCode
    {
        return AuthorizationCode::issue(
            AuthorizationCodeId::generate(new SeededRandomSource(crc32($value))),
            Digest::of($value),
            ClientId::fromString('spa'),
            UserId::generate(new SeededRandomSource(7)),
            'https://app.example/cb',
            ScopeSet::fromString('openid'),
            CodeChallenge::fromString(str_repeat('a', 43)),
            null,
            null,
            AuthenticationContext::unknown(),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            60,
        );
    }
}
