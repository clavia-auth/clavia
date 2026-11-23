<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Management;

use Clavia\Application\Management\InitialAccessTokens\IssueInitialAccessToken;
use Clavia\Application\Management\InitialAccessTokens\NewInitialAccessToken;
use Clavia\Application\Management\InitialAccessTokens\RevokeInitialAccessToken;
use Clavia\Application\Management\NotFound;
use Clavia\Domain\Client\Registration\Event\InitialAccessTokenIssued;
use Clavia\Domain\Client\Registration\Event\InitialAccessTokenRevoked;
use Clavia\Domain\Client\Registration\InitialAccessTokenId;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryInitialAccessTokenRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

final class InitialAccessTokensTest extends TestCase
{
    private InMemoryInitialAccessTokenRepository $tokens;
    private FrozenClock $clock;
    private InMemoryDomainEvents $events;

    #[\Override]
    protected function setUp(): void
    {
        $this->tokens = new InMemoryInitialAccessTokenRepository();
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $this->events = new InMemoryDomainEvents();
    }

    public function testTheSecretIsHandedOutOnceAndKeptAsItsDigest(): void
    {
        $issued = $this->issue()(new NewInitialAccessToken('Partner', 3600, 2));

        self::assertSame(43, strlen($issued->secret));
        self::assertTrue($issued->token->digest->equals(Digest::of($issued->secret)));
        self::assertSame($issued->token->id, $this->tokens->spendOne(Digest::of($issued->secret), $this->clock->now()));
        self::assertCount(1, $this->events->ofType(InitialAccessTokenIssued::class));
    }

    public function testRevokingTwiceRecordsOnce(): void
    {
        $issued = $this->issue()(new NewInitialAccessToken('Partner'));
        $revoke = new RevokeInitialAccessToken($this->tokens, $this->clock, $this->events);

        $revoke($issued->token->id);
        $this->clock->advance(60);
        $revoke($issued->token->id);

        self::assertCount(1, $this->events->ofType(InitialAccessTokenRevoked::class));
        self::assertEquals(
            $issued->token->createdAt,
            $this->tokens->find($issued->token->id)?->revokedAt,
            'The first instant is kept.',
        );
        self::assertNull($this->tokens->spendOne(Digest::of($issued->secret), $this->clock->now()));
    }

    public function testRevokingAnUnknownTokenIsNotFound(): void
    {
        $this->expectException(NotFound::class);

        (new RevokeInitialAccessToken($this->tokens, $this->clock, $this->events))(
            InitialAccessTokenId::generate(new SeededRandomSource(7)),
        );
    }

    private function issue(): IssueInitialAccessToken
    {
        $random = new SeededRandomSource(1);

        return new IssueInitialAccessToken(
            $this->tokens,
            new SecretGenerator($random),
            $random,
            $this->clock,
            $this->events,
        );
    }
}
