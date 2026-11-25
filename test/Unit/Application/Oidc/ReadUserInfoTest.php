<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Oidc;

use ClaviaTest\Support\Fake\FakeDpopProofVerifier;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryDpopNonces;
use ClaviaTest\Support\Fake\InMemoryDpopReplayCache;
use ClaviaTest\Support\Fake\InMemoryRoleRepository;
use Clavia\Application\OAuth2\Dpop\ReadDpopProof;
use Clavia\Application\OAuth2\ProtectedResource\CheckSenderConstraint;
use Clavia\Application\OAuth2\ProtectedResource\PresentedCredentials;
use Clavia\Application\Oidc\ApplicationClaims;
use Clavia\Application\Oidc\UserInfo\ReadUserInfo;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\Profile;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\BearerErrorCode;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAccessTokenRepository;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class ReadUserInfoTest extends TestCase
{
    private FrozenClock $clock;
    private InMemoryAccessTokenRepository $tokens;
    private InMemoryUserRepository $users;
    private ReadUserInfo $readUserInfo;
    private User $user;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $this->tokens = new InMemoryAccessTokenRepository();
        $this->users = new InMemoryUserRepository();
        $this->readUserInfo = new ReadUserInfo(
            $this->tokens,
            $this->users,
            $this->clock,
            self::senderConstraint(),
            'https://auth.clavia.test/oidc/userinfo',
            new ApplicationClaims(new InMemoryClientRepository(), new InMemoryRoleRepository()),
        );

        $this->user = User::register(
            UserId::generate(new SeededRandomSource(1)),
            'ada@example.com',
            null,
            $this->clock->now(),
        );
        $this->user->changeProfile(Profile::of(name: 'Ada'), $this->clock->now());
        $this->users->save($this->user);
    }

    public function testTheClaimsAreWhatTheScopeOfTheTokenReleases(): void
    {
        $this->token('t-1', 'openid profile');

        self::assertSame(
            ['sub' => $this->user->id->value, 'name' => 'Ada', 'updated_at' => $this->clock->now()->getTimestamp()],
            ($this->readUserInfo)(PresentedCredentials::bearer('t-1'), 'GET'),
        );
    }

    public function testAnUnknownTokenIsInvalid(): void
    {
        $this->assertRefused(BearerErrorCode::InvalidToken, 'nope');
    }

    public function testAnExpiredTokenIsInvalid(): void
    {
        $this->token('t-1', 'openid');
        $this->clock->advance(3600);

        $this->assertRefused(BearerErrorCode::InvalidToken, 't-1');
    }

    public function testARevokedTokenIsInvalidAtOnce(): void
    {
        $this->token('t-1', 'openid', revokedAt: $this->clock->now());

        $this->assertRefused(BearerErrorCode::InvalidToken, 't-1');
    }

    public function testATokenThatNamesNobodyDescribesNobody(): void
    {
        $this->token('t-1', 'openid', withUser: false);

        $this->assertRefused(BearerErrorCode::InvalidToken, 't-1');
    }

    public function testADeactivatedAccountIsNoLongerDescribed(): void
    {
        $this->token('t-1', 'openid');
        $this->user->deactivate($this->clock->now());
        $this->users->save($this->user);

        $this->assertRefused(BearerErrorCode::InvalidToken, 't-1');
    }

    public function testATokenWithoutOpenidLacksTheScopeAndSaysWhichIsNeeded(): void
    {
        $this->token('t-1', 'profile');

        try {
            ($this->readUserInfo)(PresentedCredentials::bearer('t-1'), 'GET');
            self::fail('The token was accepted.');
        } catch (BearerTokenError $error) {
            self::assertSame(BearerErrorCode::InsufficientScope, $error->error);
            self::assertSame('openid', $error->requiredScope?->toString());
        }
    }

    private function token(
        string $value,
        string $scope,
        bool $withUser = true,
        ?DateTimeImmutable $revokedAt = null,
    ): void {
        $now = $this->clock->now();
        $this->tokens->add(AccessToken::reconstitute(
            AccessTokenId::generate(new SeededRandomSource(crc32($value))),
            Digest::of($value),
            ClientId::fromString('spa'),
            $withUser ? $this->user->id : null,
            null,
            null,
            ScopeSet::fromString($scope),
            $now,
            $now->modify('+3600 seconds'),
            $revokedAt,
        ));
    }

    /**
     * @param non-empty-string $token
     */
    private function assertRefused(BearerErrorCode $expected, string $token): void
    {
        try {
            ($this->readUserInfo)(PresentedCredentials::bearer($token), 'GET');
            self::fail('The token was accepted.');
        } catch (BearerTokenError $error) {
            self::assertSame($expected, $error->error);
            self::assertNull($error->requiredScope);
        }
    }

    private static function senderConstraint(): CheckSenderConstraint
    {
        $clock = new FrozenClock();

        return new CheckSenderConstraint(new ReadDpopProof(
            new FakeDpopProofVerifier(),
            new InMemoryDpopReplayCache($clock),
            new InMemoryDpopNonces($clock),
            $clock,
            60,
        ));
    }
}
