<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\RefreshTokenId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see AccessTokenRepository} must do.
 */
trait AccessTokenRepositoryContract
{
    abstract protected function tokens(): AccessTokenRepository;

    /**
     * An authorization code that exists in the storage under test, for tokens to come from.
     *
     * @param non-empty-string $value Distinct values give distinct codes.
     */
    abstract protected function aStoredCode(string $value): AuthorizationCode;

    #[Test]
    public function anAddedTokenIsReadBackWholeByItsDigest(): void
    {
        $code = $this->aStoredCode('code-1');
        $this->tokens()->add($this->aToken('token-1', $code));

        $stored = $this->tokens()->findByDigest(Digest::of('token-1'));

        self::assertNotNull($stored);
        self::assertTrue($stored->digest->equals(Digest::of('token-1')));
        self::assertTrue($stored->clientId->equals($code->clientId));
        self::assertTrue($stored->userId?->equals($code->userId));
        self::assertTrue($stored->authorizationCodeId?->equals($code->id));
        self::assertSame('openid', $stored->scope->toString());
        self::assertNull($stored->audience);
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:10Z'), $stored->issuedAt);
        self::assertEquals(new DateTimeImmutable('2026-01-15T11:00:10Z'), $stored->expiresAt);
        self::assertFalse($stored->isRevoked());
    }

    #[Test]
    public function aTokenAClientObtainedAsItselfIsReadBackWithItsAudienceAndNoSubject(): void
    {
        $code = $this->aStoredCode('code-1');
        $this->tokens()->add(AccessToken::issueToClient(
            AccessTokenId::generate(new SeededRandomSource(9)),
            Digest::of('machine-token'),
            $code->clientId,
            Audience::fromString('https://invoices.example/api/'),
            ScopeSet::fromString('invoices:read'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            600,
        ));

        $stored = $this->tokens()->findByDigest(Digest::of('machine-token'));

        self::assertNotNull($stored);
        self::assertNull($stored->userId);
        self::assertNull($stored->authorizationCodeId);
        self::assertSame('https://invoices.example/api/', $stored->audience?->value);
        self::assertSame('invoices:read', $stored->scope->toString());
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:10:00Z'), $stored->expiresAt);
    }

    #[Test]
    public function anUnknownDigestIsNull(): void
    {
        $this->tokens()->add($this->aToken('token-1', $this->aStoredCode('code-1')));

        self::assertNull($this->tokens()->findByDigest(Digest::of('token-2')));
    }

    #[Test]
    public function revokingByCodeRevokesItsTokensAndOnlyThose(): void
    {
        $leaked = $this->aStoredCode('code-1');
        $other = $this->aStoredCode('code-2');
        $this->tokens()->add($this->aToken('token-1', $leaked));
        $this->tokens()->add($this->aToken('token-2', $other));
        $now = new DateTimeImmutable('2026-01-15T10:05:00Z');

        $revoked = $this->tokens()->revokeIssuedFrom($leaked->id, $now);

        self::assertSame(1, $revoked);
        self::assertEquals($now, $this->tokens()->findByDigest(Digest::of('token-1'))?->revokedAt());
        self::assertFalse($this->tokens()->findByDigest(Digest::of('token-2'))?->isRevoked());
    }

    #[Test]
    public function revokingTwiceKeepsTheFirstInstant(): void
    {
        $code = $this->aStoredCode('code-1');
        $this->tokens()->add($this->aToken('token-1', $code));
        $first = new DateTimeImmutable('2026-01-15T10:05:00Z');

        $this->tokens()->revokeIssuedFrom($code->id, $first);
        $again = $this->tokens()->revokeIssuedFrom($code->id, new DateTimeImmutable('2026-01-15T10:06:00Z'));

        self::assertSame(0, $again);
        self::assertEquals($first, $this->tokens()->findByDigest(Digest::of('token-1'))?->revokedAt());
    }

    #[Test]
    public function oneTokenIsRevokedAloneAndOnce(): void
    {
        $code = $this->aStoredCode('code-1');
        $target = $this->aToken('token-1', $code);
        $this->tokens()->add($target);
        $this->tokens()->add($this->aToken('token-2', $code));
        $first = new DateTimeImmutable('2026-01-15T10:05:00Z');

        self::assertSame(1, $this->tokens()->revoke($target->id, $first));
        self::assertSame(0, $this->tokens()->revoke($target->id, new DateTimeImmutable('2026-01-15T10:06:00Z')));

        self::assertEquals($first, $this->tokens()->findByDigest(Digest::of('token-1'))?->revokedAt());
        self::assertFalse($this->tokens()->findByDigest(Digest::of('token-2'))?->isRevoked());
    }

    #[Test]
    public function revokingARefreshFamilyRevokesTheTokensThatCameWithOrFromIt(): void
    {
        $code = $this->aStoredCode('code-1');
        $family = RefreshTokenId::generate(new SeededRandomSource(41));
        $now = new DateTimeImmutable('2026-01-15T10:05:00Z');
        $this->tokens()->add(AccessToken::issueFromCode(
            AccessTokenId::generate(new SeededRandomSource(42)),
            Digest::of('with-the-family'),
            $code,
            ScopeSet::fromString('openid'),
            new DateTimeImmutable('2026-01-15T10:00:10Z'),
            3600,
            $family,
        ));
        $this->tokens()->add($this->aToken('without-a-family', $code));

        self::assertSame(
            $family->value,
            $this->tokens()->findByDigest(Digest::of('with-the-family'))?->refreshFamilyId?->value,
        );
        self::assertSame(1, $this->tokens()->revokeFamily($family, $now));
        self::assertEquals($now, $this->tokens()->findByDigest(Digest::of('with-the-family'))?->revokedAt());
        self::assertFalse($this->tokens()->findByDigest(Digest::of('without-a-family'))?->isRevoked());
        self::assertSame(0, $this->tokens()->revokeFamily($family, $now));
    }

    #[Test]
    public function revokingACodeThatMintedNothingRevokesNothing(): void
    {
        $code = $this->aStoredCode('code-1');

        $revoked = $this->tokens()->revokeIssuedFrom($code->id, new DateTimeImmutable('2026-01-15T10:05:00Z'));

        self::assertSame(0, $revoked);
    }

    private function aToken(string $value, AuthorizationCode $code): AccessToken
    {
        return AccessToken::issueFromCode(
            AccessTokenId::generate(new SeededRandomSource(crc32($value))),
            Digest::of($value),
            $code,
            ScopeSet::fromString('openid'),
            new DateTimeImmutable('2026-01-15T10:00:10Z'),
            3600,
        );
    }
}
