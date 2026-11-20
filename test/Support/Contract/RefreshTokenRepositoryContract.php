<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\Refresh;
use Clavia\Domain\OAuth2\RefreshToken;
use Clavia\Domain\OAuth2\RefreshTokenId;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see RefreshTokenRepository} must do.
 */
trait RefreshTokenRepositoryContract
{
    abstract protected function refreshTokens(): RefreshTokenRepository;

    /**
     * An authorization code that exists in the storage under test, for a family to start from.
     *
     * @param non-empty-string $value Distinct values give distinct codes.
     */
    abstract protected function aStoredCode(string $value): AuthorizationCode;

    /**
     * Run `$work` in a transaction of the storage under test.
     *
     * @template T
     * @param callable(): T $work
     * @return T
     */
    abstract protected function transactional(callable $work): mixed;

    #[Test]
    public function aFamilysFirstTokenIsReadBackWhole(): void
    {
        $code = $this->aStoredCode('code-1');
        $token = $this->aFirstToken('refresh-1', $code);
        $this->refreshTokens()->add($token);

        $stored = $this->refreshTokens()->findByDigest(Digest::of('refresh-1'));

        self::assertNotNull($stored);
        self::assertTrue($stored->id->equals($token->id));
        self::assertTrue($stored->familyId->equals($token->id), 'The first token is its own family.');
        self::assertTrue($stored->clientId->equals($code->clientId));
        self::assertTrue($stored->userId->equals($code->userId));
        self::assertTrue($stored->authorizationCodeId?->equals($code->id));
        self::assertSame('openid profile', $stored->scope->toString());
        self::assertNull($stored->audience);
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $stored->issuedAt);
        self::assertEquals(new DateTimeImmutable('2026-01-15T11:00:00Z'), $stored->expiresAt);
        self::assertEquals(new DateTimeImmutable('2026-01-15T12:00:00Z'), $stored->familyExpiresAt);
        self::assertNull($stored->usedAt());
        self::assertNull($stored->revokedAt());
        self::assertNull($this->refreshTokens()->findByDigest(Digest::of('refresh-2')));
    }

    #[Test]
    public function aSpentTokenIsKeptAndKnownAsSpent(): void
    {
        $code = $this->aStoredCode('code-1');
        $this->refreshTokens()->add($this->aFirstToken('refresh-1', $code));
        $now = new DateTimeImmutable('2026-01-15T10:30:00Z');

        $this->transactional(function () use ($now): void {
            $locked = $this->refreshTokens()->lockForRefresh(Digest::of('refresh-1'));
            self::assertNotNull($locked);
            $locked->spend($now);
            $this->refreshTokens()->save($locked);
        });

        $stored = $this->refreshTokens()->findByDigest(Digest::of('refresh-1'));
        self::assertEquals($now, $stored?->usedAt());
        self::assertSame(Refresh::Replayed, $stored?->examine($code->clientId, $now));
    }

    #[Test]
    public function revokingAFamilyRevokesEveryGenerationAndNothingElse(): void
    {
        $code = $this->aStoredCode('code-1');
        $first = $this->aFirstToken('refresh-1', $code);
        $second = $first->succeededBy(
            RefreshTokenId::generate(new SeededRandomSource(22)),
            Digest::of('refresh-2'),
            $first->scope,
            new DateTimeImmutable('2026-01-15T10:30:00Z'),
            3600,
        );
        $unrelated = $this->aFirstToken('refresh-3', $this->aStoredCode('code-2'));
        foreach ([$first, $second, $unrelated] as $token) {
            $this->refreshTokens()->add($token);
        }
        $now = new DateTimeImmutable('2026-01-15T10:40:00Z');

        self::assertSame(2, $this->refreshTokens()->revokeFamily($first->familyId, $now));
        self::assertSame(0, $this->refreshTokens()->revokeFamily($first->familyId, $now->modify('+1 minute')));

        self::assertEquals($now, $this->refreshTokens()->findByDigest(Digest::of('refresh-1'))?->revokedAt());
        self::assertEquals($now, $this->refreshTokens()->findByDigest(Digest::of('refresh-2'))?->revokedAt());
        self::assertNull($this->refreshTokens()->findByDigest(Digest::of('refresh-3'))?->revokedAt());
    }

    #[Test]
    public function aSuccessorKeepsTheFamilyAndItsDeadline(): void
    {
        $first = $this->aFirstToken('refresh-1', $this->aStoredCode('code-1'));
        $this->refreshTokens()->add($first->succeededBy(
            RefreshTokenId::generate(new SeededRandomSource(22)),
            Digest::of('refresh-2'),
            ScopeSet::fromString('openid'),
            new DateTimeImmutable('2026-01-15T11:30:00Z'),
            3600,
        ));

        $stored = $this->refreshTokens()->findByDigest(Digest::of('refresh-2'));

        self::assertTrue($stored?->familyId->equals($first->id));
        self::assertSame('openid', $stored?->scope->toString());
        // The idle limit would be 12:30; the family's deadline comes first.
        self::assertEquals(new DateTimeImmutable('2026-01-15T12:00:00Z'), $stored?->expiresAt);
        self::assertEquals($first->familyExpiresAt, $stored?->familyExpiresAt);
    }

    #[Test]
    public function revokingByCodeRevokesTheSessionItStarted(): void
    {
        $leaked = $this->aStoredCode('code-1');
        $this->refreshTokens()->add($this->aFirstToken('refresh-1', $leaked));
        $this->refreshTokens()->add($this->aFirstToken('refresh-2', $this->aStoredCode('code-2')));
        $now = new DateTimeImmutable('2026-01-15T10:40:00Z');

        self::assertSame(1, $this->refreshTokens()->revokeIssuedFrom($leaked->id, $now));

        self::assertEquals($now, $this->refreshTokens()->findByDigest(Digest::of('refresh-1'))?->revokedAt());
        self::assertNull($this->refreshTokens()->findByDigest(Digest::of('refresh-2'))?->revokedAt());
    }

    /**
     * @param non-empty-string $value
     */
    private function aFirstToken(string $value, AuthorizationCode $code): RefreshToken
    {
        return RefreshToken::startFamily(
            RefreshTokenId::generate(new SeededRandomSource(crc32($value))),
            Digest::of($value),
            $code,
            ScopeSet::fromString('openid profile'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            3600,
            7200,
        );
    }
}
