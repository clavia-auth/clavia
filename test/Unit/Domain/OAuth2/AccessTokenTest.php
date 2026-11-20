<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\OAuth2;

use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class AccessTokenTest extends TestCase
{
    public function testATokenMintedFromACodeBelongsToTheCodesClientAndUser(): void
    {
        $code = $this->aCode();

        $token = $this->issueFrom($code);

        self::assertTrue($token->clientId->equals($code->clientId));
        self::assertTrue($token->userId?->equals($code->userId));
        self::assertTrue($token->authorizationCodeId?->equals($code->id));
        self::assertSame('openid', $token->scope->toString());
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:10Z'), $token->issuedAt);
        self::assertEquals(new DateTimeImmutable('2026-01-15T11:00:10Z'), $token->expiresAt);
        self::assertSame('Bearer', AccessToken::TOKEN_TYPE);
    }

    public function testItIsActiveUntilItExpires(): void
    {
        $token = $this->issueFrom($this->aCode());

        self::assertTrue($token->isActiveAt(new DateTimeImmutable('2026-01-15T11:00:09Z')));
        self::assertFalse($token->isActiveAt(new DateTimeImmutable('2026-01-15T11:00:10Z')));
        self::assertTrue($token->isExpiredAt(new DateTimeImmutable('2026-01-15T11:00:10Z')));
    }

    public function testARevokedTokenIsNotActiveHoweverFresh(): void
    {
        $fresh = $this->issueFrom($this->aCode());
        $revoked = AccessToken::reconstitute(
            $fresh->id,
            $fresh->digest,
            $fresh->clientId,
            $fresh->userId,
            $fresh->authorizationCodeId,
            $fresh->audience,
            $fresh->scope,
            $fresh->issuedAt,
            $fresh->expiresAt,
            new DateTimeImmutable('2026-01-15T10:00:20Z'),
        );

        self::assertTrue($revoked->isRevoked());
        self::assertFalse($revoked->isActiveAt(new DateTimeImmutable('2026-01-15T10:00:21Z')));
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:20Z'), $revoked->revokedAt());
    }

    public function testTheLifetimeLeftCountsDownAndStopsAtZero(): void
    {
        $token = $this->issueFrom($this->aCode());

        self::assertSame(3600, $token->lifetimeFrom(new DateTimeImmutable('2026-01-15T10:00:10Z')));
        self::assertSame(1, $token->lifetimeFrom(new DateTimeImmutable('2026-01-15T11:00:09Z')));
        self::assertSame(0, $token->lifetimeFrom(new DateTimeImmutable('2026-01-15T12:00:00Z')));
    }

    private function issueFrom(AuthorizationCode $code): AccessToken
    {
        return AccessToken::issueFromCode(
            AccessTokenId::generate(new SeededRandomSource(3)),
            Digest::of('the-token'),
            $code,
            $code->scope,
            new DateTimeImmutable('2026-01-15T10:00:10Z'),
            3600,
        );
    }

    private function aCode(): AuthorizationCode
    {
        return AuthorizationCode::issue(
            AuthorizationCodeId::generate(new SeededRandomSource(1)),
            Digest::of('the-code'),
            ClientId::fromString('spa'),
            UserId::generate(new SeededRandomSource(2)),
            'https://app.example/cb',
            ScopeSet::fromString('openid'),
            CodeChallenge::fromString(str_repeat('a', 43)),
            null,
            AuthenticationContext::unknown(),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            60,
        );
    }
}
