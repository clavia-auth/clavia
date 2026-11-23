<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Client\Registration;

use Clavia\Domain\Client\Registration\InitialAccessToken;
use Clavia\Domain\Client\Registration\InitialAccessTokenId;
use Clavia\Domain\Client\Registration\InitialAccessTokenState;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class InitialAccessTokenTest extends TestCase
{
    private const string NOW = '2026-01-15T10:00:00Z';

    public function testANewTokenIsActiveUntilItExpires(): void
    {
        $token = self::issue(lifetime: 3600);

        self::assertSame(0, $token->uses);
        self::assertEquals(new DateTimeImmutable('2026-01-15T11:00:00Z'), $token->expiresAt);
        self::assertTrue($token->isUsableAt(new DateTimeImmutable('2026-01-15T10:59:59Z')));
        self::assertSame(InitialAccessTokenState::Expired, $token->stateAt($token->expiresAt));
    }

    public function testATokenWithEveryUseSpentIsUsedUp(): void
    {
        $token = self::stored(maxUses: 2, uses: 2);

        self::assertSame(InitialAccessTokenState::UsedUp, $token->stateAt(new DateTimeImmutable(self::NOW)));
        self::assertFalse($token->isUsableAt(new DateTimeImmutable(self::NOW)));
    }

    public function testRevokedComesFirstAndKeepsItsFirstInstant(): void
    {
        $first = new DateTimeImmutable('2026-01-15T10:30:00Z');
        $token = self::stored(maxUses: 1, uses: 1)->revoke($first);

        $again = $token->revoke(new DateTimeImmutable('2026-01-16T10:00:00Z'));

        $later = new DateTimeImmutable('2026-02-01T00:00:00Z');
        self::assertSame(InitialAccessTokenState::Revoked, $again->stateAt($later));
        self::assertEquals($first, $again->revokedAt);
    }

    /**
     * @param callable(): InitialAccessToken $make
     */
    #[DataProvider('outOfBounds')]
    public function testWhatIsOutOfBoundsIsRefused(callable $make): void
    {
        $this->expectException(InvalidValue::class);

        $make();
    }

    /** @return iterable<string, array{callable(): InitialAccessToken}> */
    public static function outOfBounds(): iterable
    {
        yield 'an empty description' => [static fn (): InitialAccessToken => self::issue(description: '')];
        yield 'a description of 121 bytes' => [static fn (): InitialAccessToken => self::issue(str_repeat('é', 61))];
        yield 'a control character' => [static fn (): InitialAccessToken => self::issue("a\tb")];
        yield 'no use' => [static fn (): InitialAccessToken => self::issue(maxUses: 0)];
        yield 'more than 1000 uses' => [static fn (): InitialAccessToken => self::issue(maxUses: 1001)];
        yield 'under a minute' => [static fn (): InitialAccessToken => self::issue(lifetime: 59)];
        yield 'over ninety days' => [static fn (): InitialAccessToken => self::issue(lifetime: 7_776_001)];
        yield 'more uses spent than allowed' => [static fn (): InitialAccessToken => self::stored(maxUses: 1, uses: 2)];
    }

    private static function issue(
        string $description = 'Partner',
        int $maxUses = 1,
        int $lifetime = 604_800,
    ): InitialAccessToken {
        return InitialAccessToken::issue(
            InitialAccessTokenId::generate(new SeededRandomSource(1)),
            Digest::of('secret'),
            $description,
            new DateTimeImmutable(self::NOW),
            $lifetime,
            $maxUses,
        );
    }

    private static function stored(int $maxUses, int $uses): InitialAccessToken
    {
        return InitialAccessToken::reconstitute(
            InitialAccessTokenId::generate(new SeededRandomSource(1)),
            Digest::of('secret'),
            'Partner',
            new DateTimeImmutable('2026-01-14T10:00:00Z'),
            new DateTimeImmutable('2026-01-21T10:00:00Z'),
            $maxUses,
            $uses,
            null,
        );
    }
}
