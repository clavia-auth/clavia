<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Client\Registration\InitialAccessToken;
use Clavia\Domain\Client\Registration\InitialAccessTokenId;
use Clavia\Domain\Client\Registration\InitialAccessTokenRepository;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\PageRequest;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see InitialAccessTokenRepository} must do, run against the double and PostgreSQL.
 */
trait InitialAccessTokenRepositoryContract
{
    abstract protected function initialAccessTokens(): InitialAccessTokenRepository;

    #[Test]
    public function anIssuedTokenIsReadBackWhole(): void
    {
        $token = $this->anInitialAccessToken('partner', maxUses: 3);
        $this->initialAccessTokens()->add($token);

        $stored = $this->initialAccessTokens()->find($token->id);

        self::assertNotNull($stored);
        self::assertTrue($stored->digest->equals(Digest::of('partner')));
        self::assertSame('For partner', $stored->description);
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $stored->createdAt);
        self::assertEquals(new DateTimeImmutable('2026-01-22T10:00:00Z'), $stored->expiresAt);
        self::assertSame(3, $stored->maxUses);
        self::assertSame(0, $stored->uses);
        self::assertNull($stored->revokedAt);
        $unknown = InitialAccessTokenId::generate(new SeededRandomSource(99));
        self::assertNull($this->initialAccessTokens()->find($unknown));
    }

    #[Test]
    public function aUseIsSpentUntilNoneIsLeft(): void
    {
        $token = $this->anInitialAccessToken('partner', maxUses: 2);
        $this->initialAccessTokens()->add($token);
        $now = new DateTimeImmutable('2026-01-16T10:00:00Z');

        $first = $this->initialAccessTokens()->spendOne(Digest::of('partner'), $now);
        $second = $this->initialAccessTokens()->spendOne(Digest::of('partner'), $now);
        $third = $this->initialAccessTokens()->spendOne(Digest::of('partner'), $now);

        self::assertTrue($first?->equals($token->id));
        self::assertTrue($second?->equals($token->id));
        self::assertNull($third, 'Used up.');
        self::assertSame(2, $this->initialAccessTokens()->find($token->id)?->uses);
    }

    #[Test]
    public function anExpiredRevokedOrUnknownTokenSpendsNothing(): void
    {
        $expired = $this->anInitialAccessToken('expired');
        $revoked = $this->anInitialAccessToken('revoked');
        $this->initialAccessTokens()->add($expired);
        $this->initialAccessTokens()->add($revoked);
        $this->initialAccessTokens()->save($revoked->revoke(new DateTimeImmutable('2026-01-15T11:00:00Z')));
        $now = new DateTimeImmutable('2026-01-16T10:00:00Z');

        self::assertNull($this->initialAccessTokens()->spendOne(Digest::of('expired'), $expired->expiresAt));
        self::assertNull($this->initialAccessTokens()->spendOne(Digest::of('revoked'), $now));
        self::assertNull($this->initialAccessTokens()->spendOne(Digest::of('nobody'), $now));
        self::assertSame(0, $this->initialAccessTokens()->find($expired->id)?->uses);
        self::assertSame(0, $this->initialAccessTokens()->find($revoked->id)?->uses);
    }

    #[Test]
    public function savingRecordsARevocationAndNeverTheUses(): void
    {
        $token = $this->anInitialAccessToken('partner', maxUses: 5);
        $this->initialAccessTokens()->add($token);
        $now = new DateTimeImmutable('2026-01-16T10:00:00Z');
        $spent = $this->initialAccessTokens()->spendOne(Digest::of('partner'), $now);
        self::assertNotNull($spent);

        // A copy read before the use was spent: saving it must not give the use back.
        $this->initialAccessTokens()->save($token->revoke(new DateTimeImmutable('2026-01-17T10:00:00Z')));

        $stored = $this->initialAccessTokens()->find($token->id);
        self::assertEquals(new DateTimeImmutable('2026-01-17T10:00:00Z'), $stored?->revokedAt);
        self::assertSame(1, $stored?->uses);
    }

    #[Test]
    public function tokensArePagedNewestFirstAndSearchedByDescription(): void
    {
        $this->initialAccessTokens()->add($this->anInitialAccessToken('older', at: '2026-01-14T10:00:00Z'));
        $this->initialAccessTokens()->add($this->anInitialAccessToken('newer', at: '2026-01-15T10:00:00Z'));

        $all = $this->initialAccessTokens()->page(PageRequest::of(1, 10, ''));
        $found = $this->initialAccessTokens()->page(PageRequest::of(1, 10, 'OLDER'));

        self::assertSame(2, $all->total);
        self::assertSame(['For newer', 'For older'], array_map(
            static fn (InitialAccessToken $token): string => $token->description,
            $all->items,
        ));
        self::assertSame(1, $found->total);
        self::assertSame('For older', $found->items[0]->description);
    }

    /** @param positive-int $maxUses */
    private function anInitialAccessToken(
        string $secret,
        int $maxUses = 1,
        string $at = '2026-01-15T10:00:00Z',
    ): InitialAccessToken {
        return InitialAccessToken::issue(
            InitialAccessTokenId::generate(new SeededRandomSource(crc32($secret))),
            Digest::of($secret),
            'For ' . $secret,
            new DateTimeImmutable($at),
            604_800,
            $maxUses,
        );
    }
}
