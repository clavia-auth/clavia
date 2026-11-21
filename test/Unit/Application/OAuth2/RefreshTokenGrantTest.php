<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\OAuth2;

use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Application\OAuth2\Token\IssuedToken;
use Clavia\Application\OAuth2\Token\RefreshTokenGrant;
use Clavia\Application\OAuth2\Token\UserScope;
use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\ErrorCode;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\OAuth2\RefreshToken;
use Clavia\Domain\OAuth2\RefreshTokenId;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAccessTokenRepository;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryRefreshTokenRepository;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryRoleRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RefreshTokenGrantTest extends TestCase
{
    private const string TOKEN = 'the-refresh-token';

    private FrozenClock $clock;
    private InMemoryRefreshTokenRepository $refreshTokens;
    private InMemoryAccessTokenRepository $tokens;
    private InMemoryUserRepository $users;
    private RefreshTokenGrant $grant;
    private Client $client;
    private User $user;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $random = new SeededRandomSource(1);
        $transactions = new InMemoryTransactionManager();
        $this->refreshTokens = new InMemoryRefreshTokenRepository($transactions);
        $this->tokens = new InMemoryAccessTokenRepository();
        $this->users = new InMemoryUserRepository();
        $apis = new InMemoryResourceServerRepository();
        $this->grant = new RefreshTokenGrant(
            $this->refreshTokens,
            $this->tokens,
            $this->users,
            $transactions,
            new SecretGenerator($random),
            $random,
            $this->clock,
            new UserScope(
                $apis,
                new InMemoryRoleRepository($apis, $this->users),
                ScopeSet::fromString('openid profile email'),
            ),
            3600,
            86_400,
            new InMemoryDomainEvents(),
        );

        $this->client = self::refreshing('spa');
        $this->user = User::register(
            UserId::generate(new SeededRandomSource(2)),
            'jane@example.com',
            null,
            $this->clock->now(),
        );
        $this->users->save($this->user);
        $this->refreshTokens->add(RefreshToken::startFamily(
            RefreshTokenId::generate(new SeededRandomSource(3)),
            Digest::of(self::TOKEN),
            AuthorizationCode::issue(
                AuthorizationCodeId::generate(new SeededRandomSource(4)),
                Digest::of('the-code'),
                $this->client->id,
                $this->user->id,
                Clients::REDIRECT_URI,
                ScopeSet::fromString('openid profile'),
                CodeChallenge::fromString(str_repeat('a', 43)),
                null,
                null,
                AuthenticationContext::unknown(),
                $this->clock->now(),
                60,
            ),
            ScopeSet::fromString('openid profile'),
            $this->clock->now(),
            86_400,
            172_800,
        ));
    }

    public function testItIsTheRefreshTokenGrantAndPublicClientsMayUseIt(): void
    {
        self::assertSame(GrantType::RefreshToken, $this->grant->type());
        self::assertContains(ClientAuthMethod::None, $this->grant->acceptedAuthMethods());
    }

    public function testARefreshSpendsTheTokenAndIssuesAPairWithoutAnIdToken(): void
    {
        $this->clock->advance(60);

        $issued = $this->refresh();

        self::assertNull($issued->idToken);
        self::assertNotNull($issued->refreshToken);
        self::assertSame('openid profile', $issued->scope->toString());
        self::assertSame(3600, $issued->expiresIn);
        self::assertNotNull($this->stored(self::TOKEN)->usedAt());
        $successor = $this->stored($issued->refreshToken);
        self::assertTrue($successor->familyId->equals($this->stored(self::TOKEN)->familyId));
        self::assertNull($successor->usedAt());
        $access = $this->tokens->findByDigest(Digest::of($issued->accessToken));
        self::assertTrue($access?->refreshFamilyId?->equals($successor->familyId));
        self::assertTrue($access?->userId?->equals($this->user->id));
    }

    public function testAReplayRevokesTheFamilyAndWhatItMinted(): void
    {
        $issued = $this->refresh();

        $error = $this->refusal();

        self::assertSame(ErrorCode::InvalidGrant, $error->error);
        self::assertNotNull($this->stored(self::TOKEN)->revokedAt());
        self::assertNotNull($issued->refreshToken);
        self::assertNotNull($this->stored($issued->refreshToken)->revokedAt());
        self::assertTrue($this->tokens->findByDigest(Digest::of($issued->accessToken))?->isRevoked());
    }

    /**
     * @param array<string, string> $overrides
     */
    #[DataProvider('refusalsThatLeaveTheTokenAlone')]
    public function testARefusalBeforeTheSpendLeavesTheTokenAsItWas(array $overrides, ErrorCode $expected): void
    {
        self::assertSame($expected, $this->refusal($overrides)->error);

        self::assertNull($this->stored(self::TOKEN)->usedAt());
        self::assertNull($this->stored(self::TOKEN)->revokedAt());
        self::assertSame([], $this->tokens->all());
    }

    /** @return iterable<string, array{array<string, string>, ErrorCode}> */
    public static function refusalsThatLeaveTheTokenAlone(): iterable
    {
        yield 'a wider scope' => [['scope' => 'openid profile email'], ErrorCode::InvalidScope];
        yield 'a malformed scope' => [['scope' => 'open"id'], ErrorCode::InvalidScope];
        yield 'an unknown token' => [['refresh_token' => 'never-issued'], ErrorCode::InvalidGrant];
    }

    public function testAnotherClientPresentingItBurnsNothing(): void
    {
        $error = $this->refusal([], self::refreshing('other'));

        self::assertSame(ErrorCode::InvalidGrant, $error->error);
        self::assertNull($this->stored(self::TOKEN)->usedAt());
        self::assertNotNull($this->refresh()->refreshToken);
    }

    public function testADeactivatedAccountIsRefusedAndTheTokenKept(): void
    {
        $this->user->deactivate($this->clock->now());
        $this->users->save($this->user);

        self::assertSame(ErrorCode::InvalidGrant, $this->refusal()->error);
        self::assertNull($this->stored(self::TOKEN)->usedAt());
    }

    public function testAMissingTokenIsAnInvalidRequest(): void
    {
        $this->expectExceptionObject(OAuth2Error::invalidRequest("Missing 'refresh_token' parameter."));

        $this->grant->issue(RequestParameters::fromMap(['grant_type' => 'refresh_token']), $this->client);
    }

    /**
     * @param array<string, string> $overrides
     */
    private function refresh(array $overrides = [], ?Client $as = null): IssuedToken
    {
        return $this->grant->issue(
            RequestParameters::fromMap($overrides + ['grant_type' => 'refresh_token', 'refresh_token' => self::TOKEN]),
            $as ?? $this->client,
        );
    }

    /**
     * @param array<string, string> $overrides
     */
    private function refusal(array $overrides = [], ?Client $as = null): OAuth2Error
    {
        try {
            $this->refresh($overrides, $as);
        } catch (OAuth2Error $error) {
            return $error;
        }

        self::fail('A token was issued.');
    }

    private static function refreshing(string $clientId): Client
    {
        return Clients::public($clientId, grantTypes: [GrantType::AuthorizationCode, GrantType::RefreshToken]);
    }

    private function stored(string $value): RefreshToken
    {
        $token = $this->refreshTokens->findByDigest(Digest::of($value));
        self::assertNotNull($token);

        return $token;
    }
}
