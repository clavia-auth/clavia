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
use Clavia\Application\OAuth2\Token\AuthorizationCodeGrant;
use Clavia\Application\OAuth2\Token\IssuedToken;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\OAuth2\ErrorCode;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAccessTokenRepository;
use ClaviaTest\Support\Fake\InMemoryAuthorizationCodeRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AuthorizationCodeGrantTest extends TestCase
{
    private const string CODE = 'the-authorization-code';
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    private FrozenClock $clock;
    private InMemoryAuthorizationCodeRepository $codes;
    private InMemoryAccessTokenRepository $tokens;
    private InMemoryUserRepository $users;
    private AuthorizationCodeGrant $grant;
    private Client $client;
    private User $user;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $random = new SeededRandomSource(1);
        $transactions = new InMemoryTransactionManager();
        $this->codes = new InMemoryAuthorizationCodeRepository($transactions);
        $this->tokens = new InMemoryAccessTokenRepository();
        $this->users = new InMemoryUserRepository();
        $this->grant = new AuthorizationCodeGrant(
            $this->codes,
            $this->tokens,
            $this->users,
            $transactions,
            new SecretGenerator($random),
            $random,
            $this->clock,
            3600,
        );

        $this->client = Clients::public('spa');
        $this->user = User::register(
            UserId::generate(new SeededRandomSource(2)),
            'jane@example.com',
            null,
            $this->clock->now(),
        );
        $this->users->save($this->user);
        $this->codes->add(AuthorizationCode::issue(
            AuthorizationCodeId::generate(new SeededRandomSource(3)),
            Digest::of(self::CODE),
            $this->client->id,
            $this->user->id,
            Clients::REDIRECT_URI,
            ScopeSet::fromString('openid profile'),
            CodeChallenge::forVerifier(CodeVerifier::fromString(self::VERIFIER)),
            $this->clock->now(),
            60,
        ));
    }

    public function testItIsTheAuthorizationCodeGrantAndAcceptsEveryClientAuthentication(): void
    {
        self::assertSame(GrantType::AuthorizationCode, $this->grant->type());
        self::assertSame(
            [ClientAuthMethod::ClientSecretBasic, ClientAuthMethod::ClientSecretPost, ClientAuthMethod::None],
            $this->grant->acceptedAuthMethods(),
        );
    }

    public function testAValidExchangeYieldsABearerTokenForTheScopeOfTheCode(): void
    {
        $token = $this->exchange();

        self::assertSame('Bearer', $token->tokenType);
        self::assertSame(3600, $token->expiresIn);
        self::assertSame('openid profile', $token->scope->toString());
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $token->accessToken);
    }

    public function testTheTokenIsStoredAsADigestAndTracedToItsCode(): void
    {
        $token = $this->exchange();

        $stored = $this->tokens->findByDigest(Digest::of($token->accessToken));
        self::assertNotNull($stored);
        self::assertCount(1, $this->tokens->all());
        self::assertSame('spa', $stored->clientId->value);
        self::assertTrue($stored->userId?->equals($this->user->id));
        self::assertTrue($stored->authorizationCodeId?->equals($this->codes->all()[0]->id));
        self::assertEquals(new DateTimeImmutable('2026-01-15T11:00:00Z'), $stored->expiresAt);
    }

    public function testTheCodeIsSpent(): void
    {
        $this->clock->advance(10);

        $this->exchange();

        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:10Z'), $this->codes->all()[0]->usedAt());
    }

    public function testAMissingCodeIsAnInvalidRequest(): void
    {
        $error = $this->refusal(['code' => null]);

        self::assertSame(ErrorCode::InvalidRequest, $error->error);
        self::assertNull($this->codes->all()[0]->usedAt());
    }

    public function testAnUnknownCodeIsAnInvalidGrant(): void
    {
        $error = $this->refusal(['code' => 'never-issued']);

        self::assertSame(ErrorCode::InvalidGrant, $error->error);
        self::assertNull($this->codes->all()[0]->usedAt());
    }

    public function testACodePresentedByAnotherClientIsRefusedAndStaysRedeemable(): void
    {
        $error = $this->refusal([], Clients::public('other'));

        self::assertSame(ErrorCode::InvalidGrant, $error->error);
        self::assertNull($this->codes->all()[0]->usedAt());
        self::assertSame([], $this->tokens->all());

        // The rightful client is not locked out by the stranger's attempt.
        self::assertSame(3600, $this->exchange()->expiresIn);
    }

    public function testAnExpiredCodeIsRefusedWithoutBeingSpent(): void
    {
        $this->clock->advance(60);

        $error = $this->refusal();

        self::assertSame(ErrorCode::InvalidGrant, $error->error);
        self::assertNull($this->codes->all()[0]->usedAt());
    }

    public function testAReplayIsRefusedAndRevokesTheTokenTheCodeAlreadyProduced(): void
    {
        $token = $this->exchange();
        $this->clock->advance(5);

        $error = $this->refusal();

        self::assertSame(ErrorCode::InvalidGrant, $error->error);
        $stored = $this->tokens->findByDigest(Digest::of($token->accessToken));
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:05Z'), $stored?->revokedAt());
        self::assertCount(1, $this->tokens->all());
    }

    public function testAStrangerReplayingASpentCodeRevokesNothing(): void
    {
        $token = $this->exchange();

        $this->refusal([], Clients::public('other'));

        self::assertFalse($this->tokens->findByDigest(Digest::of($token->accessToken))?->isRevoked());
    }

    public function testEveryKindOfBadCodeIsTheSameAnswer(): void
    {
        $unknown = $this->refusal(['code' => 'never-issued']);
        $foreign = $this->refusal([], Clients::public('other'));
        $this->exchange();
        $replayed = $this->refusal();

        self::assertSame($unknown->description, $foreign->description);
        self::assertSame($unknown->description, $replayed->description);
    }

    /**
     * The code is spent before these are looked at, so a wrong guess burns it: an
     * attacker holding a stolen code gets one attempt, not a search.
     *
     * @param array<string, string|null> $overrides
     */
    #[DataProvider('failuresAfterTheCodeIsSpent')]
    public function testAFailedProofBurnsTheCode(array $overrides, ErrorCode $expected): void
    {
        $error = $this->refusal($overrides);

        self::assertSame($expected, $error->error);
        self::assertNotNull($this->codes->all()[0]->usedAt());
        self::assertSame([], $this->tokens->all());

        // Even a correct second attempt is now a replay.
        self::assertSame(ErrorCode::InvalidGrant, $this->refusal()->error);
    }

    /** @return iterable<string, array{array<string, string|null>, ErrorCode}> */
    public static function failuresAfterTheCodeIsSpent(): iterable
    {
        yield 'another redirect URI' => [['redirect_uri' => 'https://evil.example/cb'], ErrorCode::InvalidGrant];
        yield 'no redirect URI' => [['redirect_uri' => null], ErrorCode::InvalidGrant];
        yield 'no verifier' => [['code_verifier' => null], ErrorCode::InvalidRequest];
        yield 'a malformed verifier' => [['code_verifier' => 'too-short'], ErrorCode::InvalidRequest];
        yield 'the wrong verifier' => [['code_verifier' => str_repeat('a', 43)], ErrorCode::InvalidGrant];
        // What `plain` would have accepted.
        yield 'the challenge as verifier' => [
            ['code_verifier' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'],
            ErrorCode::InvalidGrant,
        ];
    }

    public function testAnAccountDeactivatedSinceTheCodeWasIssuedGetsNoToken(): void
    {
        $this->user->deactivate($this->clock->now());
        $this->users->save($this->user);

        $error = $this->refusal();

        self::assertSame(ErrorCode::InvalidGrant, $error->error);
        self::assertSame([], $this->tokens->all());
    }

    public function testTwoCodesYieldTwoDifferentTokens(): void
    {
        $this->codes->add(AuthorizationCode::issue(
            AuthorizationCodeId::generate(new SeededRandomSource(4)),
            Digest::of('a-second-code'),
            $this->client->id,
            $this->user->id,
            Clients::REDIRECT_URI,
            ScopeSet::empty(),
            CodeChallenge::forVerifier(CodeVerifier::fromString(self::VERIFIER)),
            $this->clock->now(),
            60,
        ));

        $first = $this->exchange();
        $second = $this->exchange(['code' => 'a-second-code']);

        self::assertNotSame($first->accessToken, $second->accessToken);
        self::assertTrue($second->scope->isEmpty());
        self::assertCount(2, $this->tokens->all());
    }

    /**
     * A complete, valid token request with some parameters replaced; null removes one.
     *
     * @param array<string, string|null> $overrides
     */
    private function exchange(array $overrides = [], ?Client $as = null): IssuedToken
    {
        $form = array_filter(
            $overrides + [
                'grant_type' => 'authorization_code',
                'code' => self::CODE,
                'redirect_uri' => Clients::REDIRECT_URI,
                'code_verifier' => self::VERIFIER,
            ],
            static fn (?string $value): bool => $value !== null,
        );

        return $this->grant->issue(RequestParameters::fromMap($form), $as ?? $this->client);
    }

    /**
     * @param array<string, string|null> $overrides
     */
    private function refusal(array $overrides = [], ?Client $as = null): OAuth2Error
    {
        try {
            $this->exchange($overrides, $as);
        } catch (OAuth2Error $error) {
            return $error;
        }

        self::fail('A token was issued.');
    }
}
