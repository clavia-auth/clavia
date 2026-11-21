<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Http\Auth\AuthCookies;
use Clavia\Adapter\Secondary\IdentityProvider\GoogleIdentityProvider;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use DateTimeImmutable;

/**
 * Connections — which ways to sign in each application may use — ported from the Python
 * suite's `test_connections.py`.
 *
 * The login page for an application offers only what it enables; a password posted or a
 * provider link followed outside that list is refused, not merely hidden; a session
 * established through a connection the application does not enable does not count for
 * it; a third-party application gets the domain connections and nothing else. Then the
 * Management API: connections, the pools accounts live in, and the identities linked to
 * an account.
 */
final class ConnectionsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string CONNECTIONS = '/api/v1/connections';
    private const string CLIENTS = '/api/v1/clients';
    private const string USERS = '/api/v1/users';
    private const string THIRD_PARTY = 'tpc_partner';
    private const string SESSION_COOKIE = 'clavia_session';

    // ── What the login page offers ──────────────────────────────────────────────

    public function testTheLoginPageOffersOnlyTheApplicationsConnections(): void
    {
        $this->bootWithGoogle();
        $this->publicClient();
        $state = $this->loginStateFor();

        $everything = $this->loginPage($state);
        self::assertStringContainsString('name="password"', $everything);
        self::assertStringContainsString('Continue with Google', $everything);

        $this->restrict(ConnectionName::DEFAULT_POOL);
        self::assertStringNotContainsString('Continue with Google', $this->loginPage($state));

        $this->restrict('google');
        $page = $this->loginPage($state);
        self::assertStringNotContainsString('name="password"', $page);
        self::assertStringContainsString('Continue with Google', $page);
    }

    public function testAnApplicationWithNoConnectionsSaysSo(): void
    {
        $this->publicClient();
        $this->restrict();

        $page = $this->loginPage($this->loginStateFor());

        self::assertStringNotContainsString('name="password"', $page);
        self::assertStringContainsString('No sign-in method is available', $page);
    }

    public function testADirectVisitOffersEveryUsableConnection(): void
    {
        // No application in play: the session being made is this server's own.
        $this->bootWithGoogle();

        $page = $this->loginPage(null);

        self::assertStringContainsString('name="password"', $page);
        self::assertStringContainsString('Continue with Google', $page);
    }

    public function testASocialConnectionWithoutCredentialsIsNeverOffered(): void
    {
        // Switched on by the operator, but the deployment has no Google credentials.
        $this->publicClient();

        self::assertStringNotContainsString('Continue with Google', $this->loginPage($this->loginStateFor()));
    }

    public function testASwitchedOffConnectionIsGoneForEveryone(): void
    {
        $this->bootWithGoogle();
        $this->publicClient();
        $this->change('google', static fn (Connection $google): Connection => $google->switched(false, null, null));

        self::assertStringNotContainsString('Continue with Google', $this->loginPage($this->loginStateFor()));
        self::assertStringNotContainsString('Continue with Google', $this->loginPage(null));
    }

    // ── Refused, not merely hidden ──────────────────────────────────────────────

    public function testAPasswordIsRefusedWhenTheApplicationDoesNotEnableAPool(): void
    {
        $this->bootWithGoogle();
        $this->publicClient();
        $this->user();
        $this->restrict('google');
        $state = $this->loginStateFor();

        // The page shows no password form, so the post is built by hand — with the CSRF
        // cookie the page still set, so that the refusal is not a CSRF artefact.
        $this->get('/auth/login', ['state' => $state]);
        $response = $this->post('/auth/login', [
            'csrf_token' => (string) $this->cookie(AuthCookies::CSRF, '/auth'),
            'state' => $state,
            'email' => self::TEST_USER_EMAIL,
            'password' => self::TEST_USER_PASSWORD,
        ]);

        self::assertSame(400, $response->getStatusCode(), (string) $response->getBody());
        self::assertStringContainsString('not available for this application', (string) $response->getBody());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testAProviderLinkIsRefusedWhenTheApplicationDoesNotEnableIt(): void
    {
        $this->bootWithGoogle();
        $this->publicClient();
        $this->restrict(ConnectionName::DEFAULT_POOL);
        $state = $this->loginStateFor();

        $response = $this->get('/auth/social/google', ['state' => $state]);

        self::assertSame(400, $response->getStatusCode());
        self::assertStringContainsString('Sign-in with Google is not available', (string) $response->getBody());
        self::assertNull(self::setCookieHeader($response, AuthCookies::EXTERNAL_SIGN_IN));
    }

    public function testAProviderLinkWorksWhenEnabled(): void
    {
        $this->bootWithGoogle();
        $this->publicClient();

        $response = $this->get('/auth/social/google', ['state' => $this->loginStateFor()]);

        self::assertSame(303, $response->getStatusCode());
        self::assertStringStartsWith(
            GoogleIdentityProvider::AUTHORIZATION_ENDPOINT,
            $response->getHeaderLine('Location'),
        );
    }

    // ── Sessions remember their connection ──────────────────────────────────────

    public function testASessionThroughAConnectionTheApplicationNoLongerEnablesDoesNotCount(): void
    {
        // Signed in with a password; the application then stops accepting passwords.
        $this->publicClient();
        $this->user();
        self::assertSame(303, $this->submitLogin()->getStatusCode());
        [, $challenge] = $this->makePkcePair();
        $this->extractCode($this->get('/oauth2/authorize', $this->authorizeParams($challenge)));

        $this->restrict();

        $response = $this->get('/oauth2/authorize', $this->authorizeParams($challenge));
        self::assertSame(303, $response->getStatusCode());
        self::assertStringStartsWith('/auth/login?', $response->getHeaderLine('Location'));
        // The handle names the application, so the login page offers its (empty) list.
        $state = self::locationQuery($response)['state'] ?? null;
        self::assertIsString($state);
        self::assertSame(self::TEST_CLIENT_ID, $this->loginState($state)?->clientId?->value);
    }

    public function testASessionRecordsItsConnection(): void
    {
        $this->user();
        $this->submitLogin();

        self::assertSame('password', $this->session($this->cookie(self::SESSION_COOKIE))?->connection->value);
    }

    public function testAPasswordSignInStillWorksEndToEnd(): void
    {
        // A first-party application enabling every built-in connection: nothing changes.
        $this->publicClient();
        $this->user();

        self::assertSame(303, $this->submitLogin(state: $this->loginStateFor())->getStatusCode());
    }

    // ── Third-party applications ────────────────────────────────────────────────

    public function testAThirdPartyApplicationGetsTheDomainConnectionsOnly(): void
    {
        $this->bootWithGoogle();
        $this->thirdParty();
        $state = $this->loginStateFor(self::THIRD_PARTY);

        $page = $this->loginPage($state);
        // The default pool is a domain connection out of the box; Google is not.
        self::assertStringContainsString('name="password"', $page);
        self::assertStringNotContainsString('Continue with Google', $page);

        $this->change('google', static fn (Connection $google): Connection => $google->switched(null, true, null));
        self::assertStringContainsString('Continue with Google', $this->loginPage($state));
    }

    public function testAThirdPartyApplicationCannotBeGivenAList(): void
    {
        $this->adminToken();
        $new = [
            'client_type' => 'public',
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'redirect_uris' => ['https://p.test/cb'],
            'is_first_party' => false,
        ];

        $listed = $this->api('POST', self::CLIENTS, $new + ['connections' => ['password']]);
        self::assertSame(422, $listed->getStatusCode());

        $created = $this->api('POST', self::CLIENTS, $new);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        $client = self::json($created);
        self::assertSame([], $client['connections']);
        self::assertSame(
            422,
            $this->api(
                'PUT',
                self::CLIENTS . '/' . (string) $client['client_id'] . '/connections',
                ['connections' => ['password']],
            )->getStatusCode(),
        );
    }

    // ── Applications, through the Management API ────────────────────────────────

    public function testANewApplicationGetsEveryConnection(): void
    {
        $this->adminToken();

        $created = $this->api('POST', self::CLIENTS, [
            'client_type' => 'public',
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'redirect_uris' => ['https://a.test/cb'],
        ]);

        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        self::assertSame(['github', 'google', 'password'], self::json($created)['connections']);
    }

    public function testTheConnectionsOfAnApplicationAreReplacedWhole(): void
    {
        $this->adminToken();
        $id = (string) self::json($this->api('POST', self::CLIENTS, [
            'client_type' => 'public',
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'redirect_uris' => ['https://a.test/cb'],
            'connections' => ['password'],
        ]))['client_id'];

        $replaced = $this->api('PUT', self::CLIENTS . '/' . $id . '/connections', ['connections' => ['google']]);

        self::assertSame(200, $replaced->getStatusCode(), (string) $replaced->getBody());
        self::assertSame(['google'], self::json($replaced));
        self::assertSame(['google'], self::json($this->api('GET', self::CLIENTS . '/' . $id))['connections']);
        self::assertSame(
            404,
            $this->api('PUT', self::CLIENTS . '/' . $id . '/connections', ['connections' => ['saml']])->getStatusCode(),
        );
        self::assertSame(['google'], self::json($this->api('GET', self::CLIENTS . '/' . $id))['connections']);
    }

    // ── Connections, through the Management API ─────────────────────────────────

    public function testConnectionsAreListedWithWhatTheServerKnowsOfThem(): void
    {
        $this->adminToken();

        $listed = $this->api('GET', self::CONNECTIONS);

        self::assertSame(200, $listed->getStatusCode(), (string) $listed->getBody());
        $connections = self::json($listed);
        self::assertSame(
            ['github', 'google', 'password'],
            array_map(static fn (mixed $connection): mixed => self::at($connection, 'name'), $connections),
        );
        $password = self::named($connections, 'password');
        $google = self::named($connections, 'google');
        self::assertSame('database', self::at($password, 'strategy'));
        self::assertTrue(self::at($password, 'is_domain_connection'));
        self::assertTrue(self::at($password, 'usable'));
        self::assertFalse(self::at($google, 'configured'));
        self::assertFalse(self::at($google, 'usable'));
        self::assertNull(self::at($google, 'oidc_issuer'));

        $this->bootWithGoogle();
        $this->adminToken();
        $google = self::json($this->api('GET', self::CONNECTIONS . '/google'));
        self::assertTrue($google['configured']);
        self::assertTrue($google['usable']);
    }

    public function testAConnectionIsSwitchedAndRenamed(): void
    {
        $this->adminToken();

        $patched = $this->api('PATCH', self::CONNECTIONS . '/github', [
            'is_enabled' => false,
            'is_domain_connection' => true,
            'display_name' => 'GitHub (staff)',
        ]);

        self::assertSame(200, $patched->getStatusCode(), (string) $patched->getBody());
        $body = self::json($patched);
        self::assertFalse($body['is_enabled']);
        self::assertTrue($body['is_domain_connection']);
        self::assertSame('GitHub (staff)', $body['display_name']);
        self::assertFalse($body['usable']);
        self::assertSame(
            404,
            $this->api('PATCH', self::CONNECTIONS . '/saml', ['is_enabled' => true])->getStatusCode(),
        );
        // Creating one needs a strategy and a display name: the contract is strict.
        self::assertSame(422, $this->api('POST', self::CONNECTIONS, ['name' => 'x'])->getStatusCode());
    }

    public function testTheConnectionScopesAreRequired(): void
    {
        $this->adminToken(['read:users']);

        $response = $this->api('GET', self::CONNECTIONS);

        self::assertSame(403, $response->getStatusCode());
        self::assertStringContainsString('scope="read:connections"', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testSocialConnectionsAreBuiltInAndNeverCreatedOrDeleted(): void
    {
        $this->adminToken();

        $created = $this->api('POST', self::CONNECTIONS, [
            'name' => 'gitlab',
            'display_name' => 'GitLab',
            'strategy' => 'social',
        ]);

        self::assertSame(422, $created->getStatusCode());
        self::assertSame(409, $this->api('DELETE', self::CONNECTIONS . '/google')->getStatusCode());
        self::assertSame(409, $this->api('DELETE', self::CONNECTIONS . '/password')->getStatusCode());
        self::assertSame(409, $this->api('POST', self::CONNECTIONS, [
            'name' => 'password',
            'display_name' => 'Again',
            'strategy' => 'database',
        ])->getStatusCode());
    }

    public function testAConnectionNameIsPlain(): void
    {
        $this->adminToken();

        $response = $this->api('POST', self::CONNECTIONS, [
            'name' => 'Staff Pool!',
            'display_name' => 'Staff',
            'strategy' => 'database',
        ]);

        self::assertSame(422, $response->getStatusCode());
    }

    // ── Pools: several connections with passwords ───────────────────────────────

    public function testUsersAreCreatedInAPool(): void
    {
        $this->adminToken();
        $this->makePool();

        self::assertSame('staff', $this->makeUser('jane@clavia.dev', 'staff')['connection']);
        self::assertSame('password', self::json($this->api('POST', self::USERS, [
            'email' => 'x@clavia.dev',
            'password' => 'a-good-password',
        ]))['connection']);
    }

    public function testTheSameAddressMayLiveInTwoPools(): void
    {
        $this->adminToken();
        $this->makePool();

        $first = $this->makeUser('jane@clavia.dev', 'password');
        $second = $this->makeUser('jane@clavia.dev', 'staff');

        self::assertNotSame($first['id'], $second['id']);
        self::assertSame(409, $this->api('POST', self::USERS, [
            'email' => 'jane@clavia.dev',
            'password' => 'a-good-password',
            'connection' => 'staff',
        ])->getStatusCode());
    }

    public function testAUserIsNotCreatedInAnExternalConnection(): void
    {
        $this->adminToken();

        foreach (['google' => 422, 'nope' => 404, 'Not A Name' => 422] as $connection => $status) {
            self::assertSame($status, $this->api('POST', self::USERS, [
                'email' => 'x@clavia.dev',
                'password' => 'a-good-password',
                'connection' => $connection,
            ])->getStatusCode(), $connection);
        }
    }

    public function testASignInLooksOnlyInThePoolsTheApplicationEnables(): void
    {
        // A staff account cannot sign in to an application that only enables customers.
        $this->adminToken();
        $this->publicClient();
        $this->makePool();
        $this->makeUser('jane@clavia.dev', 'staff', 'staff-password');
        $this->restrict(ConnectionName::DEFAULT_POOL);
        $state = $this->loginStateFor();

        self::assertSame(401, $this->submitLogin('jane@clavia.dev', 'staff-password', state: $state)->getStatusCode());

        $this->restrict(ConnectionName::DEFAULT_POOL, 'staff');
        self::assertSame(303, $this->submitLogin('jane@clavia.dev', 'staff-password', state: $state)->getStatusCode());
        self::assertSame('staff', $this->session($this->cookie(self::SESSION_COOKIE))?->connection->value);
    }

    public function testTheSameAddressInTwoPoolsSignsInAsWhicheverPasswordMatches(): void
    {
        $this->adminToken();
        $this->publicClient();
        $this->makePool();
        $customer = $this->makeUser('jane@clavia.dev', 'password', 'customer-password');
        $staff = $this->makeUser('jane@clavia.dev', 'staff', 'staff-password');
        $this->restrict(ConnectionName::DEFAULT_POOL, 'staff');

        $this->submitLogin('jane@clavia.dev', 'staff-password', state: $this->loginStateFor());
        self::assertSame($staff['id'], $this->session($this->cookie(self::SESSION_COOKIE))?->userId->value);

        $this->clearCookies();
        $this->submitLogin('jane@clavia.dev', 'customer-password', state: $this->loginStateFor());
        self::assertSame($customer['id'], $this->session($this->cookie(self::SESSION_COOKIE))?->userId->value);
    }

    public function testAPoolWithAccountsIsNotDeleted(): void
    {
        $this->adminToken();
        $this->makePool();
        $this->makeUser('jane@clavia.dev', 'staff');

        $response = $this->api('DELETE', self::CONNECTIONS . '/staff');

        self::assertSame(409, $response->getStatusCode());
        self::assertStringContainsString('1 account belongs', (string) $response->getBody());
    }

    public function testAnEmptyPoolIsDeletedAndNoApplicationEnablesItAfterwards(): void
    {
        $this->adminToken();
        $this->publicClient();
        $this->makePool();
        $this->restrict(ConnectionName::DEFAULT_POOL, 'staff');

        self::assertSame(204, $this->api('DELETE', self::CONNECTIONS . '/staff')->getStatusCode());

        self::assertSame(404, $this->api('GET', self::CONNECTIONS . '/staff')->getStatusCode());
        self::assertSame(
            ['password'],
            self::json($this->api('GET', self::CLIENTS . '/' . self::TEST_CLIENT_ID))['connections'],
        );
    }

    // ── The identities linked to an account ─────────────────────────────────────

    public function testIdentitiesAreListedAndUnlinked(): void
    {
        $this->adminToken();
        $user = $this->user();
        $this->link($user, 'google', 'g-1', 'u@g.test');
        $identities = self::USERS . '/' . $user->id->value . '/identities';

        self::assertSame('password', self::json($this->api('GET', self::USERS . '/' . $user->id->value))['connection']);
        $listed = self::json($this->api('GET', $identities));
        self::assertCount(1, $listed);
        self::assertSame('google', self::at($listed, 0, 'connection'));
        self::assertSame('g-1', self::at($listed, 0, 'subject'));
        self::assertSame('u@g.test', self::at($listed, 0, 'email'));

        self::assertSame(204, $this->api('DELETE', $identities . '/google')->getStatusCode());
        self::assertSame([], self::json($this->api('GET', $identities)));
        self::assertSame(404, $this->api('DELETE', $identities . '/google')->getStatusCode());
    }

    public function testTheOnlyWayIntoAnAccountIsNotUnlinked(): void
    {
        $this->adminToken();
        $external = User::registerFromProvider(
            UserId::generate($this->container()->get(RandomSource::class)),
            'ext@clavia.dev',
            ConnectionName::fromString('google'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->container()->get(UserRepository::class)->save($external);
        $this->link($external, 'google', 'g-2', null);

        $response = $this->api('DELETE', self::USERS . '/' . $external->id->value . '/identities/google');

        self::assertSame(409, $response->getStatusCode());
        self::assertStringContainsString('only way in', (string) $response->getBody());
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private function bootWithGoogle(): void
    {
        $this->boot(['CLAVIA_GOOGLE_CLIENT_ID' => 'google-client', 'CLAVIA_GOOGLE_CLIENT_SECRET' => 'google-secret']);
    }

    /** Make the test public client enable exactly these connections. */
    private function restrict(string ...$names): void
    {
        /** @var ClientRepository $clients */
        $clients = $this->container()->get(ClientRepository::class);
        $client = $clients->find(ClientId::fromString(self::TEST_CLIENT_ID));
        self::assertNotNull($client);
        $clients->save($client->withConnections(array_values(array_map(ConnectionName::fromString(...), $names))));
    }

    /**
     * @param \Closure(Connection): Connection $change
     */
    private function change(string $name, \Closure $change): void
    {
        /** @var ConnectionRepository $connections */
        $connections = $this->container()->get(ConnectionRepository::class);
        $connection = $connections->find(ConnectionName::fromString($name));
        self::assertNotNull($connection);
        $connections->save($change($connection));
    }

    /** Start an authorization request with nobody signed in; the login page's handle. */
    private function loginStateFor(string $clientId = self::TEST_CLIENT_ID): string
    {
        [, $challenge] = $this->makePkcePair();
        $response = $this->get('/oauth2/authorize', $this->authorizeParams($challenge, ['client_id' => $clientId]));
        self::assertSame(303, $response->getStatusCode(), (string) $response->getBody());
        $state = self::locationQuery($response)['state'] ?? null;
        self::assertIsString($state);

        return $state;
    }

    private function loginPage(?string $state): string
    {
        return html_entity_decode((string) $this->get('/auth/login', $state === null ? [] : ['state' => $state])
            ->getBody());
    }

    private function thirdParty(): void
    {
        $this->container()->get(ClientRepository::class)->save(Client::register(
            ClientId::fromString(self::THIRD_PARTY),
            'Partner',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString(self::TEST_REDIRECT_URI)],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));
    }

    private function makePool(string $name = 'staff'): void
    {
        $created = $this->api('POST', self::CONNECTIONS, [
            'name' => $name,
            'display_name' => ucfirst($name),
            'strategy' => 'database',
        ]);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        self::assertSame(self::CONNECTIONS . '/' . $name, $created->getHeaderLine('Location'));
    }

    /** @return array<array-key, mixed> */
    private function makeUser(string $email, string $connection, string $password = 'a-good-password'): array
    {
        $created = $this->api('POST', self::USERS, [
            'email' => $email,
            'password' => $password,
            'connection' => $connection,
        ]);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());

        return self::json($created);
    }

    private function link(User $user, string $connection, string $subject, ?string $email): void
    {
        $this->container()->get(ExternalIdentityRepository::class)->add(ExternalIdentity::link(
            AssertedIdentity::of(ConnectionName::fromString($connection), $subject, $email, true),
            $user->id,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));
    }

    /**
     * The connection of that name in a listing; the test fails when there is none.
     *
     * @param array<array-key, mixed> $listing
     *
     * @return array<array-key, mixed>
     */
    private static function named(array $listing, string $name): array
    {
        foreach (array_keys($listing) as $key) {
            if (is_array($listing[$key]) && self::at($listing[$key], 'name') === $name) {
                return $listing[$key];
            }
        }

        self::fail(sprintf("No connection named '%s' is listed.", $name));
    }

    /** A member of a JSON document, by path; null when it is not there. */
    private static function at(mixed $document, string|int ...$path): mixed
    {
        foreach ($path as $key) {
            if (! is_array($document) || ! array_key_exists($key, $document)) {
                return null;
            }
            /** @var mixed $document */
            $document = $document[$key];
        }

        return $document;
    }
}
