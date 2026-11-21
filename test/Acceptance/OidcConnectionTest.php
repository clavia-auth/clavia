<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\UserRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\Fake\FakeOpenIdProvider;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Laminas\Diactoros\Response\JsonResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * OpenID Connect connections — any provider, registered by an operator — ported from the
 * Python suite's `test_oidc_connection.py`.
 *
 * The provider is {@see FakeOpenIdProvider} on the fake wire: discovery, the token
 * endpoint and the JWKS. It signs its ID tokens with a key of its own, so what these
 * tests prove is that Clavia checks the signature, the issuer, the audience, the expiry
 * and the nonce — and turns a good token into an account in the right connection.
 */
final class OidcConnectionTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string CONNECTIONS = '/api/v1/connections';
    private const string NAME = 'acme-idp';
    private const string SECRET = 'shh-the-idp-secret';
    private const string SESSION_COOKIE = 'clavia_session';

    private FakeOpenIdProvider $idp;
    private FakeHttpClient $wire;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->idp = new FakeOpenIdProvider();
        $this->wire = new FakeHttpClient($this->idp);
        $this->boot();
        $this->container()->setService(ClientInterface::class, $this->wire);
        // The fake provider's host is on the public internet; everything else resolves to
        // nothing, so only an address written into a URL is refused.
        $this->container()->setService(OutboundUrlPolicy::class, new OutboundUrlPolicy(
            false,
            static fn (string $host): array => $host === 'idp.example' ? ['93.184.216.34'] : [],
        ));
        $this->adminToken();
    }

    // ── Registering ─────────────────────────────────────────────────────────────

    public function testRegistrationDiscoversTheProviderAndSealsTheSecret(): void
    {
        $connection = $this->registerAcme();

        self::assertSame('oidc', $connection['strategy']);
        self::assertTrue($connection['configured']);
        self::assertTrue($connection['usable']);
        self::assertSame(FakeOpenIdProvider::ISSUER, $connection['oidc_issuer']);
        self::assertSame($this->idp->clientId, $connection['oidc_client_id']);
        self::assertSame('openid profile email', $connection['oidc_scope']);
        self::assertArrayNotHasKey('oidc_client_secret', $connection);
        $row = TestStorage::database()->fetchOne(
            'SELECT oidc_token_endpoint, oidc_jwks_uri, oidc_client_secret_encrypted FROM connections'
            . ' WHERE name = :name',
            ['name' => self::NAME],
        );
        self::assertIsArray($row);
        self::assertSame(FakeOpenIdProvider::TOKEN_ENDPOINT, $row['oidc_token_endpoint']);
        self::assertSame(FakeOpenIdProvider::JWKS_URI, $row['oidc_jwks_uri']);
        // Encrypted at rest, and not with the plaintext lying about in it.
        self::assertIsString($row['oidc_client_secret_encrypted']);
        self::assertStringNotContainsString(self::SECRET, $row['oidc_client_secret_encrypted']);
    }

    public function testAnIssuerThatDoesNotAnswerIsRefused(): void
    {
        $response = $this->registerConnection(['name' => 'elsewhere', 'oidc_issuer' => 'https://elsewhere.example']);

        self::assertSame(422, $response->getStatusCode());
        self::assertStringContainsString('elsewhere.example', (string) self::document($response)['detail']);
    }

    #[DataProvider('issuersNotToFetch')]
    public function testAnIssuerTheServerMustNotFetchIsRefused(string $issuer): void
    {
        // An admin form must not become a request forger against the server's network.
        $response = $this->registerConnection(['name' => 'sneaky', 'oidc_issuer' => $issuer]);

        self::assertSame(422, $response->getStatusCode(), (string) $response->getBody());
        self::assertStringStartsWith('The issuer must', (string) self::document($response)['detail']);
        self::assertSame([], $this->wire->requests, 'Nothing was fetched.');
    }

    /** @return iterable<string, array{string}> */
    public static function issuersNotToFetch(): iterable
    {
        yield 'not https' => ['http://idp.example'];
        yield 'localhost' => ['https://localhost:8000'];
        yield 'the cloud metadata service' => ['https://169.254.169.254'];
        yield 'loopback' => ['https://127.0.0.1'];
        yield 'a private address' => ['https://10.0.0.5'];
        yield 'IPv6 loopback' => ['https://[::1]'];
        yield 'an internal name' => ['https://admin.internal'];
    }

    public function testTheDiscoveryDocumentCannotAimTheServerInside(): void
    {
        // The document is an arbitrary server's answer: it does not get to aim fetches.
        $this->idp->discoveryDocument = ['jwks_uri' => 'https://169.254.169.254/latest/meta-data/']
            + $this->idp->discovery();

        $response = $this->registerConnection(['name' => 'sneaky']);

        self::assertSame(422, $response->getStatusCode());
        self::assertStringContainsString('jwks_uri', (string) self::document($response)['detail']);
    }

    public function testRegistrationNeedsEveryOidcSetting(): void
    {
        $response = $this->api('POST', self::CONNECTIONS, [
            'name' => 'half',
            'display_name' => 'Half',
            'strategy' => 'oidc',
            'oidc_issuer' => FakeOpenIdProvider::ISSUER,
        ]);

        self::assertSame(422, $response->getStatusCode());
    }

    public function testThePoolTakesNoOidcSettings(): void
    {
        $response = $this->api('POST', self::CONNECTIONS, [
            'name' => 'staff',
            'display_name' => 'Staff',
            'strategy' => 'database',
            'oidc_issuer' => FakeOpenIdProvider::ISSUER,
        ]);

        self::assertSame(422, $response->getStatusCode());
    }

    public function testAChangeToTheProviderSettingsIsDiscoveredAgain(): void
    {
        $this->registerAcme();
        $before = count($this->wire->requests);

        $patched = $this->api('PATCH', self::CONNECTIONS . '/' . self::NAME, ['oidc_client_id' => 'another-id']);

        self::assertSame(200, $patched->getStatusCode(), (string) $patched->getBody());
        self::assertSame('another-id', self::json($patched)['oidc_client_id']);
        $discovery = $this->wire->requests[$before] ?? null;
        self::assertNotNull($discovery, 'Discovery ran again.');
        self::assertSame(FakeOpenIdProvider::DISCOVERY_URL, (string) $discovery->getUri());
        self::assertSame(
            422,
            $this->api('PATCH', self::CONNECTIONS . '/' . self::NAME, ['oidc_issuer' => 'https://10.0.0.5'])
                ->getStatusCode(),
        );
        self::assertSame(
            422,
            $this->api('PATCH', self::CONNECTIONS . '/password', ['oidc_client_id' => 'x'])->getStatusCode(),
            'A pool has no provider settings.',
        );
    }

    public function testTheLoginPageOffersTheProvider(): void
    {
        $this->registerAcme();

        self::assertStringContainsString(
            'Continue with Acme SSO',
            html_entity_decode((string) $this->get('/auth/login')->getBody()),
        );
    }

    // ── Signing in ──────────────────────────────────────────────────────────────

    public function testASignInCreatesAnAccountInTheConnection(): void
    {
        $this->registerAcme();

        $response = $this->finish($this->start());

        self::assertSame(303, $response->getStatusCode(), (string) $response->getBody());
        $user = $this->users()->findByEmail(ConnectionName::fromString(self::NAME), 'ada@idp.example');
        self::assertNotNull($user);
        self::assertNull($user->passwordHash());
        self::assertTrue($user->isEmailVerified());
        $identity = $this->container()->get(ExternalIdentityRepository::class)
            ->find(ConnectionName::fromString(self::NAME), 'idp-user-1');
        self::assertTrue($identity?->userId->equals($user->id));
        $session = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($session);
        self::assertTrue($session->userId->equals($user->id));
        self::assertSame(self::NAME, $session->connection->value);
        self::assertSame(['ext'], array_map(static fn ($method): string => $method->value, $session->methods));
        // PKCE went out with the code exchange; the secret went to the provider, never the browser.
        self::assertCount(1, $this->idp->tokenRequests);
        self::assertNotSame('', $this->idp->tokenRequests[0]['code_verifier'] ?? '');
        self::assertSame(self::SECRET, $this->idp->tokenRequests[0]['client_secret'] ?? null);
        self::assertSame(
            'https://auth.clavia.test/auth/social/' . self::NAME . '/callback',
            $this->idp->tokenRequests[0]['redirect_uri'] ?? null,
        );
    }

    /**
     * @param \Closure(FakeOpenIdProvider): void $tamper
     */
    #[DataProvider('untrustworthyTokens')]
    public function testAnUntrustworthyIdTokenSignsNobodyIn(\Closure $tamper): void
    {
        $this->registerAcme();
        $state = $this->start();
        $tamper($this->idp);

        $response = $this->finish($state);

        self::assertSame(400, $response->getStatusCode());
        self::assertStringContainsString('Could not complete sign-in with Acme SSO', (string) $response->getBody());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
        self::assertSame(0, TestStorage::database()->fetchValue('SELECT count(*) FROM users'));
    }

    /** @return iterable<string, array{\Closure(FakeOpenIdProvider): void}> */
    public static function untrustworthyTokens(): iterable
    {
        yield 'from another issuer' => [static function (FakeOpenIdProvider $idp): void {
            $idp->claims = ['iss' => 'https://evil.example'];
        }];
        yield 'for another audience' => [static function (FakeOpenIdProvider $idp): void {
            $idp->claims = ['aud' => 'somebody-else'];
        }];
        // The nonce binds the token to this sign-in: one minted elsewhere lacks it.
        yield 'without the nonce' => [static function (FakeOpenIdProvider $idp): void {
            $idp->nonce = null;
        }];
        yield "with another sign-in's nonce" => [static function (FakeOpenIdProvider $idp): void {
            $idp->nonce = 'another-nonce';
        }];
        yield 'expired' => [static function (FakeOpenIdProvider $idp): void {
            $idp->claims = ['exp' => time() - 120];
        }];
        // Same kid, another key: the published JWKS still holds the real one.
        yield 'signed by another key' => [static function (FakeOpenIdProvider $idp): void {
            $idp->signingKey = 1;
            $idp->claimedKey = 0;
        }];
    }

    public function testASwitchedOffProviderIsGone(): void
    {
        $this->registerAcme();

        self::assertSame(
            200,
            $this->api('PATCH', self::CONNECTIONS . '/' . self::NAME, ['is_enabled' => false])->getStatusCode(),
        );

        self::assertSame(404, $this->get('/auth/social/' . self::NAME)->getStatusCode());
        self::assertStringNotContainsString('Acme SSO', (string) $this->get('/auth/login')->getBody());
    }

    public function testAProviderWithAccountsIsNotDeleted(): void
    {
        $this->registerAcme();
        self::assertSame(303, $this->finish($this->start())->getStatusCode());

        $response = $this->api('DELETE', self::CONNECTIONS . '/' . self::NAME);

        self::assertSame(409, $response->getStatusCode());
        self::assertStringContainsString('1 account belongs', (string) self::document($response)['detail']);
    }

    public function testAnUnusedProviderIsDeleted(): void
    {
        $this->registerAcme();

        self::assertSame(204, $this->api('DELETE', self::CONNECTIONS . '/' . self::NAME)->getStatusCode());
        self::assertSame(404, $this->api('GET', self::CONNECTIONS . '/' . self::NAME)->getStatusCode());
        $connections = $this->container()->get(ConnectionRepository::class);
        self::assertNull($connections->find(ConnectionName::fromString(self::NAME)));
    }

    public function testAProviderThatStopsAnsweringIsLoggedAndReportedGenerically(): void
    {
        $this->registerAcme();
        $state = $this->start();
        $this->wire->answerWith(
            static fn (RequestInterface $request): ResponseInterface => new JsonResponse(['error' => 'down'], 503),
        );

        $response = $this->finish($state);

        self::assertSame(400, $response->getStatusCode());
        self::assertTrue($this->logger->hasRecordContaining('answered 503'));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /**
     * Register an OIDC connection pointed at the fake provider, with `$overrides`.
     *
     * @param array<string, mixed> $overrides
     */
    private function registerConnection(array $overrides = []): ResponseInterface
    {
        return $this->api('POST', self::CONNECTIONS, $overrides + [
            'name' => self::NAME,
            'display_name' => 'Acme SSO',
            'strategy' => 'oidc',
            'is_domain_connection' => true,
            'oidc_issuer' => FakeOpenIdProvider::ISSUER,
            'oidc_client_id' => $this->idp->clientId,
            'oidc_client_secret' => self::SECRET,
        ]);
    }

    /** @return array<array-key, mixed> */
    private function registerAcme(): array
    {
        $created = $this->registerConnection();
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());

        return self::json($created);
    }

    /**
     * Begin the sign-in, and have the fake provider echo the nonce it was sent, as a real
     * one would. The `state` the provider would send back.
     */
    private function start(): string
    {
        $response = $this->get('/auth/social/' . self::NAME);
        self::assertSame(303, $response->getStatusCode(), (string) $response->getBody());
        $location = $response->getHeaderLine('Location');
        self::assertStringStartsWith(FakeOpenIdProvider::AUTHORIZATION_ENDPOINT . '?', $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        self::assertSame($this->idp->clientId, $query['client_id'] ?? null);
        self::assertSame('S256', $query['code_challenge_method'] ?? null);
        $nonce = $query['nonce'] ?? null;
        $state = $query['state'] ?? null;
        self::assertIsString($nonce);
        self::assertIsString($state);
        $this->idp->nonce = $nonce;

        return $state;
    }

    private function finish(string $state): ResponseInterface
    {
        return $this->get('/auth/social/' . self::NAME . '/callback', ['code' => 'idp-code', 'state' => $state]);
    }

    private function users(): UserRepository
    {
        return $this->container()->get(UserRepository::class);
    }
}
