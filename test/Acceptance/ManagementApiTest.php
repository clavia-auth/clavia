<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Http\Management\ManagementContract;
use Clavia\Adapter\Primary\Http\OpenApi\Operation;
use Clavia\Application\Management\ManagementPermission;
use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Mezzio\Router\RouteCollector;

/**
 * The Management API (`/api/v1/*`), end to end — ported from the Python suite's
 * `test_management_api.py`, with the contract checks this implementation adds.
 *
 * Two halves. The first is about who gets in at all: this surface is a machine plane,
 * authenticated by a token for *this* API and by nothing else. The second is the CRUD,
 * where the recurring themes are that a secret appears exactly once and that a
 * registration that could never work is refused where it is written.
 *
 * Every response is checked against `docs/openapi/management-api.yaml`
 * ({@see ManagementFixtures::api()}): a body or status the contract does not describe
 * fails the test that received it.
 */
final class ManagementApiTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string USERS = '/api/v1/users';
    private const string CLIENTS = '/api/v1/clients';
    private const string APIS = '/api/v1/resource-servers';

    // ── Getting in ──────────────────────────────────────────────────────────────

    public function testNoCredentialsGetABareChallenge(): void
    {
        // RFC 6750 §3.1: a request carrying nothing gets a challenge, not a diagnosis.
        $response = $this->api('GET', self::USERS);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Bearer realm="' . self::MANAGEMENT_API . '"', $response->getHeaderLine('WWW-Authenticate'));
        self::assertSame([], self::document($response));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    public function testUnknownTokenIsRefused(): void
    {
        $response = $this->api('GET', self::USERS, token: 'not-a-real-token');

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_token', self::document($response)['error']);
        self::assertStringContainsString('error="invalid_token"', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testAMalformedAuthorizationHeaderIsABadRequest(): void
    {
        $response = $this->api('GET', self::USERS, headers: ['Authorization' => 'Bearer two words']);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_request', self::document($response)['error']);
    }

    public function testTokenForAnotherApiIsRefused(): void
    {
        // Audience before scope: `read:users` on another API is a different permission.
        $client = $this->m2mClient();
        $this->grantClient($client, $this->anApi('https://elsewhere.test/', ['read:users']), 'read:users');
        $this->managementApi();
        $token = self::json($this->requestMachineToken(['audience' => 'https://elsewhere.test/']))['access_token'];
        self::assertIsString($token);

        $response = $this->api('GET', self::USERS, token: $token);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_token', self::document($response)['error']);
    }

    public function testTokenWithNoAudienceIsRefused(): void
    {
        // No grant issues such a token any more — the client credentials grant requires
        // an audience — so the row is written directly: this side has to hold on its own.
        $this->managementApi();
        $this->m2mClient();
        TestStorage::database()->execute(
            <<<'SQL'
                INSERT INTO oauth2_access_tokens (id, token_hash, client_id, scope, audience, expires_at)
                VALUES (gen_random_uuid(), :hash, :client_id, :scope, NULL, now() + interval '1 hour')
                SQL,
            [
                'hash' => Digest::of('issued-for-no-api')->toString(),
                'client_id' => self::TEST_M2M_CLIENT_ID,
                'scope' => implode(' ', self::allScopes()),
            ],
        );

        self::assertSame(401, $this->api('GET', self::USERS, token: 'issued-for-no-api')->getStatusCode());
    }

    public function testRevokedTokenIsRefused(): void
    {
        $token = $this->adminToken();
        TestStorage::database()->execute(
            'UPDATE oauth2_access_tokens SET revoked_at = now() WHERE token_hash = :hash',
            ['hash' => Digest::of($token)->toString()],
        );

        self::assertSame(401, $this->api('GET', self::USERS)->getStatusCode());
    }

    public function testMissingScopeIsRefusedWithTheScopeNamed(): void
    {
        $this->adminToken(['read:clients']);

        $response = $this->api('GET', self::USERS);

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('insufficient_scope', self::document($response)['error']);
        self::assertStringContainsString('scope="read:users"', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testTheScopeIsCheckedBeforeTheBody(): void
    {
        // A caller that may not create users learns nothing about what a user looks like.
        $this->adminToken(['read:users']);

        $response = $this->api('POST', self::USERS, rawBody: '{not json');

        self::assertSame(403, $response->getStatusCode());
    }

    public function testSessionCookieIsNotAccepted(): void
    {
        // The load-bearing property of this surface. A session is authority over
        // `/auth/*` and nothing else: a browser attaches a cookie to every request to its
        // origin, which is what makes CSRF possible; a bearer token has to be put there
        // deliberately by code holding it.
        $this->user();
        self::assertSame(303, $this->submitLogin()->getStatusCode());
        self::assertNotNull($this->cookie('clavia_session'));

        $response = $this->api('GET', self::USERS);

        self::assertSame(401, $response->getStatusCode());
        self::assertStringStartsWith('Bearer', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testTokenInTheQueryStringIsNotAccepted(): void
    {
        // RFC 6750 §2.3 exists and is deliberately not implemented: a token in a URL ends
        // up in access logs, referrers and browser history.
        $token = $this->adminToken();

        self::assertSame(401, $this->api('GET', self::USERS, query: ['access_token' => $token], token: '')
            ->getStatusCode());
    }

    public function testTokenIsRefusedOnceItsSubjectIsDeactivated(): void
    {
        // Machine tokens have no subject; this checks the path a user's token will take.
        $token = $this->adminToken();
        $user = $this->user();
        TestStorage::database()->execute(
            'UPDATE oauth2_access_tokens SET user_id = :user_id WHERE token_hash = :hash',
            ['user_id' => $user->id->value, 'hash' => Digest::of($token)->toString()],
        );
        self::assertSame(200, $this->api('GET', self::USERS)->getStatusCode());

        TestStorage::database()->execute('UPDATE users SET is_active = false WHERE id = :id', [
            'id' => $user->id->value,
        ]);

        self::assertSame(401, $this->api('GET', self::USERS)->getStatusCode());
    }

    public function testManagementScopesAreTheApisPermissions(): void
    {
        $api = $this->managementApi();

        self::assertEqualsCanonicalizing(self::allScopes(), $api->permissionScopes()->toList());
        self::assertTrue($api->isSystem);
    }

    public function testEveryOperationOfTheContractIsRoutedAndGuarded(): void
    {
        // Without a token, every operation the document describes answers with a
        // challenge: it is routed, and the middleware stands in front of it.
        $contract = $this->container()->get(ManagementContract::class);
        foreach ($contract->operations() as $operation) {
            $path = strtr($operation->path->template, [
                '{user_id}' => '6f1c8a52-1b1e-4c8e-9d38-0f2b3d7c9e10',
                '{client_id}' => 'some-client',
                '{resource_server_id}' => 'rs_aaaaaaaaaaaaaaaa',
            ]);

            $response = $this->api($operation->method, $path, token: '');

            self::assertSame(401, $response->getStatusCode(), (string) $operation);
        }
    }

    public function testEveryManagementRouteIsDescribedByTheContract(): void
    {
        $contract = $this->container()->get(ManagementContract::class);
        $routes = $this->container()->get(RouteCollector::class)->getRoutes();
        $described = array_map(
            static fn (Operation $operation): string => (string) $operation,
            $contract->operations(),
        );

        $routed = [];
        foreach ($routes as $route) {
            if (! str_starts_with($route->getPath(), '/api/')) {
                continue;
            }
            foreach ($route->getAllowedMethods() ?? [] as $method) {
                $routed[] = $method . ' ' . $route->getPath();
            }
        }

        self::assertEqualsCanonicalizing($described, $routed);
    }

    // ── Reading the request ────────────────────────────────────────────────────

    public function testAParameterSentTwiceIsRefused(): void
    {
        $this->adminToken();

        $response = $this->api('GET', self::USERS . '?page=1&page=2');

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('application/problem+json', $response->getHeaderLine('Content-Type'));
        self::assertSame(
            [['parameter' => 'page', 'detail' => 'Is sent more than once.']],
            self::document($response)['errors'],
        );
    }

    public function testABodyThatIsNotJsonIsRefusedForItsMediaType(): void
    {
        $this->adminToken();

        $response = $this->api('POST', self::USERS, headers: ['Content-Type' => 'text/plain'], rawBody: 'hello');

        self::assertSame(415, $response->getStatusCode());
    }

    public function testMalformedJsonIsABadRequest(): void
    {
        $this->adminToken();

        $response = $this->api('POST', self::USERS, rawBody: '{"email":');

        self::assertSame(400, $response->getStatusCode());
        $problem = self::document($response);
        self::assertSame('about:blank', $problem['type']);
        self::assertSame('Bad Request', $problem['title']);
        self::assertSame(400, $problem['status']);
    }

    public function testABodyThatIsNotAnObjectIsRefused(): void
    {
        $this->adminToken();

        $response = $this->api('POST', self::CLIENTS, rawBody: '[]');

        self::assertSame(422, $response->getStatusCode());
        self::assertSame([['pointer' => '', 'detail' => 'Must be an object.']], self::document($response)['errors']);
    }

    public function testAContractViolationSaysWhereWithoutRepeatingTheValue(): void
    {
        $this->adminToken();

        $response = $this->api('POST', self::USERS, ['email' => 'ok@clavia.dev', 'password' => 'hunter2']);

        self::assertSame(422, $response->getStatusCode());
        /** @var list<array{pointer?: string, detail: string}> $errors */
        $errors = self::document($response)['errors'];
        self::assertSame('/password', $errors[0]['pointer'] ?? null);
        self::assertStringNotContainsString('hunter2', (string) $response->getBody());
    }

    public function testAnUnknownResourceIsNotFound(): void
    {
        $this->adminToken();

        $response = $this->api('GET', self::USERS . '/' . UserId::generate($this->random())->value);

        self::assertSame(404, $response->getStatusCode());
        self::assertSame('No such user.', self::document($response)['detail']);
    }

    // ── Users ───────────────────────────────────────────────────────────────────

    public function testUserLifecycle(): void
    {
        $this->adminToken();

        $created = $this->api('POST', self::USERS, ['email' => 'new@clavia.dev', 'password' => 'a-good-password']);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        $body = self::document($created);
        $userId = $body['id'];
        self::assertIsString($userId);
        self::assertSame(self::USERS . '/' . $userId, $created->getHeaderLine('Location'));

        // Nothing about the password comes back — not the plaintext, not the hash.
        self::assertArrayNotHasKey('password', $body);
        self::assertArrayNotHasKey('password_hash', $body);
        self::assertSame('new@clavia.dev', $body['email']);
        self::assertTrue($body['is_active']);
        self::assertTrue($body['has_password']);

        self::assertSame('new@clavia.dev', self::document($this->api('GET', self::USERS . '/' . $userId))['email']);

        $patched = $this->api('PATCH', self::USERS . '/' . $userId, ['is_active' => false, 'name' => 'Ada']);
        self::assertSame(200, $patched->getStatusCode(), (string) $patched->getBody());
        self::assertFalse(self::document($patched)['is_active']);
        self::assertSame('Ada', self::document($patched)['name']);

        $cleared = $this->api('PATCH', self::USERS . '/' . $userId, ['name' => null]);
        self::assertNull(self::document($cleared)['name']);

        self::assertSame(204, $this->api('DELETE', self::USERS . '/' . $userId)->getStatusCode());
        self::assertSame(404, $this->api('GET', self::USERS . '/' . $userId)->getStatusCode());
    }

    public function testCreatedUserCanActuallyLogIn(): void
    {
        // The password is hashed with the same primitive the login endpoint verifies.
        $this->adminToken();
        $this->api('POST', self::USERS, ['email' => 'real@clavia.dev', 'password' => 'a-good-password']);

        self::assertSame(303, $this->submitLogin('real@clavia.dev', 'a-good-password')->getStatusCode());
    }

    public function testChangingTheEmailResetsVerification(): void
    {
        $this->adminToken();
        $user = $this->user();
        $this->api('PATCH', self::USERS . '/' . $user->id->value, ['email_verified' => true]);

        $patched = $this->api('PATCH', self::USERS . '/' . $user->id->value, ['email' => 'moved@clavia.dev']);

        self::assertSame('moved@clavia.dev', self::document($patched)['email']);
        self::assertFalse(self::document($patched)['email_verified']);
    }

    public function testDuplicateEmailIsAConflict(): void
    {
        $this->adminToken();
        $this->user();

        $response = $this->api(
            'POST',
            self::USERS,
            ['email' => self::TEST_USER_EMAIL, 'password' => 'a-good-password'],
        );

        self::assertSame(409, $response->getStatusCode());
    }

    public function testInvalidEmailAndShortPasswordAreRejected(): void
    {
        $this->adminToken();

        self::assertSame(
            422,
            $this->api('POST', self::USERS, ['email' => 'not-an-email', 'password' => 'a-good-password'])
                ->getStatusCode(),
        );
        self::assertSame(
            422,
            $this->api('POST', self::USERS, ['email' => 'ok@clavia.dev', 'password' => 'short'])->getStatusCode(),
        );
        // Long enough in characters, too long for bcrypt in bytes: refused, never truncated.
        self::assertSame(
            422,
            $this->api('POST', self::USERS, ['email' => 'ok@clavia.dev', 'password' => str_repeat('é', 40)])
                ->getStatusCode(),
        );
    }

    public function testUnknownFieldsAreRejectedNotIgnored(): void
    {
        $this->adminToken();

        $response = $this->api(
            'POST',
            self::USERS,
            ['email' => 'x@clavia.dev', 'password' => 'a-good-password', 'role' => 'admin'],
        );

        self::assertSame(422, $response->getStatusCode());
        self::assertSame([['pointer' => '/role', 'detail' => 'Is not allowed.']], self::document($response)['errors']);
    }

    public function testEveryViolationIsReportedAtOnce(): void
    {
        $this->adminToken();

        $response = $this->api('POST', self::USERS, ['password' => 'short', 'name' => 5, 'role' => 'admin']);

        self::assertSame(422, $response->getStatusCode());
        self::assertEqualsCanonicalizing(
            ['/email', '/password', '/name', '/role'],
            array_column((array) self::document($response)['errors'], 'pointer'),
        );
    }

    public function testAQueryParameterTheOperationDoesNotTakeIsRefused(): void
    {
        $this->adminToken();

        $response = $this->api('GET', self::USERS, query: ['sort' => 'email']);

        self::assertSame(422, $response->getStatusCode());
        self::assertSame(
            [['parameter' => 'sort', 'detail' => 'Is not a parameter of this operation.']],
            self::document($response)['errors'],
        );
    }

    public function testABodySentToAnOperationThatTakesNoneIsRefused(): void
    {
        $this->adminToken();
        $client = self::document($this->api('POST', self::CLIENTS, [
            'client_type' => 'confidential',
            'grant_types' => ['client_credentials'],
        ]));

        $path = self::CLIENTS . '/' . (string) $client['client_id'] . '/rotate-secret';

        $response = $this->api('POST', $path, ['x' => 1]);

        self::assertSame(422, $response->getStatusCode());
    }

    public function testAUserTheTokenActsAsCannotBeDeleted(): void
    {
        $token = $this->adminToken();
        $user = $this->user();
        TestStorage::database()->execute(
            'UPDATE oauth2_access_tokens SET user_id = :user_id WHERE token_hash = :hash',
            ['user_id' => $user->id->value, 'hash' => Digest::of($token)->toString()],
        );

        self::assertSame(409, $this->api('DELETE', self::USERS . '/' . $user->id->value)->getStatusCode());
    }

    public function testUsersArePaginatedAndSearchable(): void
    {
        $this->adminToken();
        foreach (['alice@clavia.dev', 'bob@clavia.dev', 'alice@other.test', '100%@x.test'] as $address) {
            $this->container()->get(UserRepository::class)->save(User::register(
                UserId::generate($this->random()),
                $address,
                'x',
                $this->container()->get(Clock::class)->now(),
            ));
        }

        $page = self::document($this->api('GET', self::USERS, query: ['page' => '1', 'per_page' => '2']));
        self::assertIsArray($page['items']);
        self::assertCount(2, $page['items']);
        self::assertSame(4, $page['total']);
        self::assertSame(2, $page['per_page']);

        self::assertSame(2, self::document($this->api('GET', self::USERS, query: ['q' => 'ALICE']))['total']);
        // `%` is a literal, not a wildcard.
        self::assertSame(1, self::document($this->api('GET', self::USERS, query: ['q' => '100%']))['total']);
        self::assertSame(422, $this->api('GET', self::USERS, query: ['per_page' => '500'])->getStatusCode());
    }

    // ── Clients ─────────────────────────────────────────────────────────────────

    public function testCreatingAConfidentialClientReturnsItsSecretOnce(): void
    {
        $this->adminToken();

        $created = $this->api('POST', self::CLIENTS, [
            'name' => 'Billing',
            'client_type' => 'confidential',
            'grant_types' => ['client_credentials'],
        ]);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        $body = self::document($created);
        $clientId = $body['client_id'];
        $secret = $body['client_secret'];
        self::assertIsString($clientId);
        self::assertIsString($secret);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9]{32}$/D', $clientId);
        // The default for a confidential client: RFC 6749 §2.3.1 says every server supports it.
        self::assertSame('client_secret_basic', $body['token_endpoint_auth_method']);
        // A client carries no scope of its own; there is nothing of the kind to report.
        self::assertArrayNotHasKey('scope', $body);

        // Only a hash is kept, so no later read can produce it again.
        $fetched = self::document($this->api('GET', self::CLIENTS . '/' . $clientId));
        self::assertArrayNotHasKey('client_secret', $fetched);
        self::assertArrayNotHasKey('client_secret_hash', $fetched);

        // And it really authenticates — once granted an API, which is a shell operation.
        $this->grant($clientId, self::MANAGEMENT_API, 'read:users');
        $token = $this->requestMachineToken(['audience' => self::MANAGEMENT_API], [$clientId, $secret]);
        self::assertSame(200, $token->getStatusCode(), (string) $token->getBody());
    }

    public function testClientIdCannotBeChosen(): void
    {
        $this->adminToken();

        $response = $this->api('POST', self::CLIENTS, ['client_id' => 'attacker-chosen', 'client_type' => 'public']);

        self::assertSame(422, $response->getStatusCode());
    }

    public function testPublicClientGetsNoSecret(): void
    {
        $this->adminToken();

        $created = $this->api('POST', self::CLIENTS, [
            'client_type' => 'public',
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'redirect_uris' => ['https://spa.test/callback'],
        ]);

        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        self::assertNull(self::document($created)['client_secret']);
        self::assertSame('none', self::document($created)['token_endpoint_auth_method']);
    }

    public function testRotatingASecretInvalidatesTheOldOne(): void
    {
        $this->adminToken();
        $created = self::document($this->api('POST', self::CLIENTS, [
            'client_type' => 'confidential',
            'grant_types' => ['client_credentials'],
        ]));
        $clientId = (string) $created['client_id'];
        $oldSecret = (string) $created['client_secret'];
        $this->grant($clientId, self::MANAGEMENT_API, 'read:users');

        $rotated = $this->api('POST', self::CLIENTS . '/' . $clientId . '/rotate-secret');
        self::assertSame(200, $rotated->getStatusCode(), (string) $rotated->getBody());
        $newSecret = self::document($rotated)['client_secret'];
        self::assertIsString($newSecret);
        self::assertNotSame($oldSecret, $newSecret);

        $form = ['audience' => self::MANAGEMENT_API];
        self::assertSame(401, $this->requestMachineToken($form, [$clientId, $oldSecret])->getStatusCode());
        self::assertSame(200, $this->requestMachineToken($form, [$clientId, $newSecret])->getStatusCode());
    }

    public function testRotatingAPublicClientsSecretIsRefused(): void
    {
        $this->adminToken();
        $client = $this->publicClient();

        self::assertSame(
            422,
            $this->api('POST', self::CLIENTS . '/' . $client->id->value . '/rotate-secret')->getStatusCode(),
        );
    }

    public function testIncoherentRegistrationsAreRefused(): void
    {
        // Combinations that pass field by field and would fail at the first request.
        $this->adminToken();
        $cases = [
            ['client_type' => 'confidential', 'token_endpoint_auth_method' => 'none'],
            ['client_type' => 'public', 'token_endpoint_auth_method' => 'client_secret_basic'],
            ['client_type' => 'public', 'grant_types' => ['client_credentials']],
            // The code flow without a redirect URI, or with only half of it.
            ['client_type' => 'public', 'grant_types' => ['authorization_code'], 'response_types' => ['code']],
            [
                'client_type' => 'public',
                'grant_types' => ['authorization_code'],
                'redirect_uris' => ['https://spa.test/callback'],
            ],
            [
                'client_type' => 'public',
                'response_types' => ['code'],
                'redirect_uris' => ['https://spa.test/callback'],
            ],
            [
                'client_type' => 'public',
                'grant_types' => ['authorization_code'],
                'response_types' => ['code'],
                'redirect_uris' => ['/callback'],
            ],
            // Grants this server does not have yet are not in the contract.
            ['client_type' => 'public', 'grant_types' => ['refresh_token']],
        ];

        foreach ($cases as $body) {
            self::assertSame(
                422,
                $this->api('POST', self::CLIENTS, $body)->getStatusCode(),
                json_encode($body, JSON_THROW_ON_ERROR),
            );
        }
    }

    public function testPatchRechecksTheMergedRegistration(): void
    {
        // Removing the last redirect URI from a code-flow client is refused.
        $this->adminToken();
        $client = $this->publicClient();
        $path = self::CLIENTS . '/' . $client->id->value;

        self::assertSame(422, $this->api('PATCH', $path, ['redirect_uris' => []])->getStatusCode());
        $renamed = $this->api('PATCH', $path, ['name' => 'Renamed']);
        self::assertSame(200, $renamed->getStatusCode(), (string) $renamed->getBody());
        self::assertSame('Renamed', self::document($renamed)['name']);
    }

    public function testATokenCannotDeleteTheClientThatIssuedIt(): void
    {
        $this->adminToken();

        self::assertSame(409, $this->api('DELETE', self::CLIENTS . '/' . self::TEST_M2M_CLIENT_ID)->getStatusCode());
    }

    public function testDeletingAClientRemovesIt(): void
    {
        $this->adminToken();
        $client = $this->publicClient();

        self::assertSame(204, $this->api('DELETE', self::CLIENTS . '/' . $client->id->value)->getStatusCode());
        self::assertSame(
            0,
            TestStorage::database()->fetchValue(
                'SELECT count(*) FROM oauth2_clients WHERE client_id = :id',
                ['id' => $client->id->value],
            ),
        );
    }

    public function testClientsAreSearchableByIdAndName(): void
    {
        $this->adminToken();

        $byId = $this->api('GET', self::CLIENTS, query: ['q' => self::TEST_M2M_CLIENT_ID]);
        self::assertSame(1, self::document($byId)['total']);
        self::assertSame(1, self::document($this->api('GET', self::CLIENTS, query: ['q' => 'machine']))['total']);
    }

    // ── Resource servers ───────────────────────────────────────────────────────

    public function testResourceServerLifecycle(): void
    {
        $this->adminToken();

        $created = $this->api('POST', self::APIS, [
            'identifier' => 'https://invoices.test/api/',
            'name' => 'Invoices',
            'permissions' => [['value' => 'invoices:read', 'description' => 'Read invoices']],
        ]);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        $body = self::document($created);
        $id = (string) $body['id'];
        self::assertStringStartsWith('rs_', $id);
        self::assertSame(self::APIS . '/' . $id, $created->getHeaderLine('Location'));
        // Not settable by a caller: an API nobody can delete is made on the machine.
        self::assertFalse($body['is_system']);

        $patched = $this->api('PATCH', self::APIS . '/' . $id, [
            'permissions' => [['value' => 'invoices:read'], ['value' => 'invoices:write']],
        ]);
        self::assertSame(200, $patched->getStatusCode(), (string) $patched->getBody());
        $permissions = self::document($patched)['permissions'];
        self::assertIsArray($permissions);
        self::assertSame(['invoices:read', 'invoices:write'], array_column($permissions, 'value'));

        self::assertSame(204, $this->api('DELETE', self::APIS . '/' . $id)->getStatusCode());
        self::assertSame(404, $this->api('GET', self::APIS . '/' . $id)->getStatusCode());
    }

    public function testIdentifierMustBeAnAbsoluteUri(): void
    {
        $this->adminToken();

        self::assertSame(422, $this->api('POST', self::APIS, ['identifier' => 'invoices'])->getStatusCode());
        self::assertSame(
            422,
            $this->api('POST', self::APIS, ['identifier' => 'https://x.test/#frag'])->getStatusCode(),
        );
    }

    public function testDuplicatePermissionValuesAreRejected(): void
    {
        $this->adminToken();

        $response = $this->api('POST', self::APIS, [
            'identifier' => 'https://x.test/',
            'permissions' => [['value' => 'a'], ['value' => 'a']],
        ]);

        self::assertSame(422, $response->getStatusCode());
    }

    public function testDuplicateIdentifierIsAConflict(): void
    {
        $this->adminToken();

        self::assertSame(409, $this->api('POST', self::APIS, ['identifier' => self::MANAGEMENT_API])->getStatusCode());
    }

    public function testTheManagementApiCannotBeDeleted(): void
    {
        $this->adminToken();
        $api = $this->managementApi();

        self::assertSame(409, $this->api('DELETE', self::APIS . '/' . $api->id->value)->getStatusCode());
        self::assertSame(200, $this->api('GET', self::APIS . '/' . $api->id->value)->getStatusCode());
    }

    public function testTheManagementApiPermissionsCannotBeEdited(): void
    {
        // They are the server's own, declared by the code.
        $this->adminToken();
        $api = $this->managementApi();

        $response = $this->api('PATCH', self::APIS . '/' . $api->id->value, [
            'permissions' => [['value' => 'read:users']],
        ]);

        self::assertSame(409, $response->getStatusCode());
        $unchanged = self::document($this->api('GET', self::APIS . '/' . $api->id->value))['permissions'];
        self::assertIsArray($unchanged);
        self::assertEqualsCanonicalizing(self::allScopes(), array_column($unchanged, 'value'));
    }

    public function testTheManagementApiCanStillBeRenamed(): void
    {
        $this->adminToken();
        $api = $this->managementApi();

        $response = $this->api('PATCH', self::APIS . '/' . $api->id->value, ['name' => 'Admin']);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('Admin', self::document($response)['name']);
        // And registering again keeps the operator's name.
        self::assertSame('Admin', $this->managementApi()->name);
    }

    public function testApisAreSearchable(): void
    {
        $this->adminToken();

        $page = self::document($this->api('GET', self::APIS, query: ['q' => 'management']));

        self::assertSame(1, $page['total']);
        /** @var list<array{identifier: string}> $items */
        $items = $page['items'];
        self::assertSame(self::MANAGEMENT_API, $items[0]['identifier']);
    }

    public function testRegisteringAClientAndReachingAnApiEndToEnd(): void
    {
        // The whole loop, driven the way an operator would: register an API, register a
        // machine client, grant it (shell-only by design), get a token for that API.
        $this->adminToken();
        $this->api('POST', self::APIS, [
            'identifier' => 'https://reports.test/',
            'permissions' => [['value' => 'reports:read']],
        ]);
        $created = self::document($this->api('POST', self::CLIENTS, [
            'client_type' => 'confidential',
            'grant_types' => ['client_credentials'],
        ]));
        $clientId = (string) $created['client_id'];
        $this->grant($clientId, 'https://reports.test/', 'reports:read');

        $token = $this->requestMachineToken(
            ['audience' => 'https://reports.test/'],
            [$clientId, (string) $created['client_secret']],
        );

        self::assertSame('reports:read', self::json($token)['scope']);
        $stored = TestStorage::database()->fetchOne(
            'SELECT audience, user_id FROM oauth2_access_tokens WHERE client_id = :id',
            ['id' => $clientId],
        );
        self::assertSame(['audience' => 'https://reports.test/', 'user_id' => null], $stored);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /** @return list<string> */
    private static function allScopes(): array
    {
        return array_map(
            static fn (ManagementPermission $permission): string => $permission->value,
            ManagementPermission::cases(),
        );
    }

    private function grant(string $clientId, string $audience, string $scopes): void
    {
        $this->container()->get(GrantClientAccess::class)(
            ClientId::fromString($clientId),
            Audience::fromString($audience),
            ScopeSet::fromString($scopes),
        );
    }

    private function random(): RandomSource
    {
        return $this->container()->get(RandomSource::class);
    }
}
