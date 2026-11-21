<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\IdentityProvider;

use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Adapter\Secondary\IdentityProvider\IdTokenVerifier;
use Clavia\Adapter\Secondary\IdentityProvider\OidcIdentityProvider;
use Clavia\Adapter\Secondary\IdentityProvider\ProviderHttp;
use Clavia\Application\Port\IdentityProviderFailed;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\OidcSettings;
use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\Fake\FakeOpenIdProvider;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryJwksCache;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\RecordingLogger;
use ClaviaTest\Support\TestSigningKeys;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A generic OpenID provider, through {@see OidcIdentityProvider} and its
 * {@see IdTokenVerifier}: the ID token is the only thing believed, and only once its
 * signature, issuer, audience, expiry and nonce all check out.
 */
final class OidcIdentityProviderTest extends TestCase
{
    private const string REDIRECT_URI = 'https://auth.clavia.test/auth/social/acme/callback';

    private FakeOpenIdProvider $idp;
    private FakeHttpClient $http;
    private InMemoryJwksCache $cache;
    private RecordingLogger $logger;
    private CodeVerifier $verifier;
    private Nonce $nonce;

    /** @var list<string> What every host resolves to. */
    private array $addresses = ['93.184.216.34'];

    #[\Override]
    protected function setUp(): void
    {
        $this->idp = new FakeOpenIdProvider('clavia');
        $this->http = new FakeHttpClient($this->idp);
        $this->cache = new InMemoryJwksCache();
        $this->logger = new RecordingLogger();
        $this->verifier = CodeVerifier::generate(new SeededRandomSource());
        $this->nonce = Nonce::fromString('the-nonce');
        $this->idp->nonce = 'the-nonce';
    }

    public function testTheAuthorizationUrlCarriesTheCodeFlowWithPkceAndTheNonce(): void
    {
        $challenge = CodeChallenge::forVerifier($this->verifier);

        $url = $this->provider()->authorizationUrl(self::REDIRECT_URI, 'the-state', $challenge, $this->nonce);

        self::assertStringStartsWith(FakeOpenIdProvider::AUTHORIZATION_ENDPOINT . '?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        self::assertSame([
            'response_type' => 'code',
            'client_id' => 'clavia',
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => 'openid email',
            'state' => 'the-state',
            'code_challenge' => $challenge->value,
            'code_challenge_method' => 'S256',
            'nonce' => 'the-nonce',
        ], $query);
    }

    public function testAVerifiedIdTokenSaysWhoSignedIn(): void
    {
        $identity = $this->identify();

        self::assertSame('acme', $identity->provider->value);
        self::assertSame('idp-user-1', $identity->subject);
        self::assertSame('ada@idp.example', $identity->verifiedEmail());
        self::assertSame([
            'grant_type' => 'authorization_code',
            'code' => 'the-code',
            'redirect_uri' => self::REDIRECT_URI,
            'client_id' => 'clavia',
            'client_secret' => 'the-secret',
            'code_verifier' => $this->verifier->value,
        ], $this->idp->tokenRequests[0]);
        self::assertSame(
            IdTokenVerifier::JWKS_LIFETIME_SECONDS,
            $this->cache->entries[FakeOpenIdProvider::JWKS_URI]['ttl'],
        );
    }

    public function testTheProviderMustSayTheAddressIsVerified(): void
    {
        $this->idp->claims = ['email_verified' => 'true'];

        $identity = $this->identify();

        self::assertSame('ada@idp.example', $identity->email);
        self::assertNull($identity->verifiedEmail());
    }

    public function testTheKeysAreFetchedOnceAndThenCached(): void
    {
        $this->identify();
        $this->identify();

        self::assertSame(1, $this->idp->jwksFetches);
    }

    public function testAKeyRotationCostsOneFetch(): void
    {
        $this->identify();
        $this->idp->signingKey = 1;
        $this->idp->publishedKeys = [0, 1];

        self::assertSame('idp-user-1', $this->identify()->subject);
        self::assertSame(2, $this->idp->jwksFetches);
    }

    public function testAnExpiryWithinAMinuteOfClockDifferenceIsTolerated(): void
    {
        $this->idp->claims = ['exp' => time() - 30];

        self::assertSame('idp-user-1', $this->identify()->subject);
    }

    /**
     * @param \Closure(FakeOpenIdProvider): void $tamper
     */
    #[DataProvider('untrustworthyTokens')]
    public function testAnUntrustworthyIdTokenIsOneFailure(\Closure $tamper, string $logged): void
    {
        $tamper($this->idp);

        try {
            $this->identify();
            self::fail('An untrustworthy ID token was believed.');
        } catch (IdentityProviderFailed) {
            self::assertTrue($this->logger->hasRecordContaining($logged), $logged);
        }
    }

    /** @return iterable<string, array{\Closure(FakeOpenIdProvider): void, string}> */
    public static function untrustworthyTokens(): iterable
    {
        yield 'no ID token at all' => [
            static function (FakeOpenIdProvider $idp): void {
                $idp->idTokenOverride = '';
            },
            'no ID token',
        ];
        yield 'not a JWS' => [
            static function (FakeOpenIdProvider $idp): void {
                $idp->idTokenOverride = 'not-a-token';
            },
            'not a compact JWS',
        ];
        yield 'alg none' => [
            static function (FakeOpenIdProvider $idp): void {
                $idp->idTokenOverride = FakeOpenIdProvider::forged(
                    ['alg' => 'none', 'kid' => TestSigningKeys::publicJwk()->kid],
                    ['iss' => FakeOpenIdProvider::ISSUER, 'aud' => 'clavia', 'sub' => 'x', 'exp' => time() + 60],
                );
            },
            'does not verify',
        ];
        yield 'HS256 keyed with the public key' => [
            static function (FakeOpenIdProvider $idp): void {
                $jwk = TestSigningKeys::publicJwk();
                $header = ['alg' => 'HS256', 'kid' => $jwk->kid];
                $payload = ['iss' => FakeOpenIdProvider::ISSUER, 'aud' => 'clavia', 'sub' => 'x'];
                $unsigned = FakeOpenIdProvider::forged($header, $payload);
                $input = substr($unsigned, 0, (int) strrpos($unsigned, '.'));
                $idp->idTokenOverride = FakeOpenIdProvider::forged(
                    $header,
                    $payload,
                    hash_hmac('sha256', $input, json_encode($jwk->toArray(), JSON_THROW_ON_ERROR), true),
                );
            },
            'does not verify',
        ];
        yield 'signed with a key the provider does not publish' => [
            static function (FakeOpenIdProvider $idp): void {
                $idp->signingKey = 1;
            },
            'does not verify',
        ];
        yield 'another issuer' => [
            static function (FakeOpenIdProvider $idp): void {
                $idp->claims = ['iss' => 'https://evil.example'];
            },
            'issued by somebody else',
        ];
        yield 'another audience' => [
            static function (FakeOpenIdProvider $idp): void {
                $idp->claims = ['aud' => 'somebody-else'];
            },
            'another audience',
        ];
        yield 'several audiences, not authorized for this one' => [
            static function (FakeOpenIdProvider $idp): void {
                $idp->claims = ['aud' => ['clavia', 'somebody-else'], 'azp' => 'somebody-else'];
            },
            'several audiences',
        ];
        yield 'expired' => [
            static function (FakeOpenIdProvider $idp): void {
                $idp->claims = ['exp' => time() - 61];
            },
            'has expired',
        ];
        yield 'no nonce' => [
            static function (FakeOpenIdProvider $idp): void {
                $idp->nonce = null;
            },
            'nonce',
        ];
        yield "another sign-in's nonce" => [
            static function (FakeOpenIdProvider $idp): void {
                $idp->nonce = 'another-nonce';
            },
            'nonce',
        ];
        yield 'no subject' => [
            static function (FakeOpenIdProvider $idp): void {
                $idp->claims = ['sub' => null];
            },
            'no subject',
        ];
    }

    public function testAnEndpointThatNowResolvesInsideTheNetworkIsNotCalled(): void
    {
        $this->addresses = ['10.0.0.7'];

        try {
            $this->identify();
            self::fail('A token endpoint resolving to a private address was called.');
        } catch (IdentityProviderFailed) {
            self::assertSame([], $this->http->requests);
        }
    }

    private function identify(): AssertedIdentity
    {
        return $this->provider()->identify('the-code', self::REDIRECT_URI, $this->verifier, $this->nonce);
    }

    private function provider(): OidcIdentityProvider
    {
        $http = new ProviderHttp($this->http, new RequestFactory(), new StreamFactory(), $this->logger);

        return new OidcIdentityProvider(
            ConnectionName::fromString('acme'),
            OidcSettings::of(
                FakeOpenIdProvider::ISSUER,
                'clavia',
                'sealed',
                ScopeSet::fromString('openid email'),
                FakeOpenIdProvider::AUTHORIZATION_ENDPOINT,
                FakeOpenIdProvider::TOKEN_ENDPOINT,
                FakeOpenIdProvider::JWKS_URI,
            ),
            'the-secret',
            $http,
            new IdTokenVerifier($http, $this->cache, new FrozenClock(gmdate('Y-m-d\TH:i:s\Z'))),
            new OutboundUrlPolicy(false, fn (): array => $this->addresses),
        );
    }
}
