<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\ResourceServer\ClientGrant;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Application ownership and the consent screen.
 *
 * First-party applications are the operator's own: signing in is the consent. A
 * third-party application is a stranger's: every scope it asks for is put to the person,
 * the answer is remembered, and it is kept away from the Management API. The screen is
 * plain HTML on the auth origin, reached only through `/oauth2/authorize` and only with a
 * handle that names the signed-in person.
 */
final class ConsentTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string THIRD_PARTY_CLIENT_ID = 'tpc_test-third-party';
    private const string INVOICES = 'https://invoices.test/api/';

    // ── Who is asked ────────────────────────────────────────────────────────────

    public function testAFirstPartySignInNeverAsks(): void
    {
        $this->loggedIn();
        $this->publicClient();

        $response = $this->authorize(['scope' => 'openid profile email']);

        self::assertArrayHasKey('code', self::locationQuery($response));
        self::assertSame([], $this->storedConsents());
    }

    public function testAThirdPartyApplicationIsSentToTheConsentScreen(): void
    {
        $this->loggedIn();
        $this->thirdPartyClient();

        $state = $this->consentState($this->asThirdParty('openid email'));
        $page = $this->get('/auth/consent', ['state' => $state]);

        self::assertSame(StatusCodeInterface::STATUS_OK, $page->getStatusCode());
        $body = (string) $page->getBody();
        self::assertStringContainsString('Partner Analytics', $body);
        self::assertStringContainsString(self::TEST_USER_EMAIL, $body);
        self::assertStringContainsString('See your email address', $body);
        self::assertStringContainsString('Sign you in and know who you are', $body);
        // No script anywhere on this origin's pages, and the response says so; the
        // decision ends at the application, so its origin may be reached.
        self::assertStringNotContainsString('<script', $body);
        $policy = $page->getHeaderLine('Content-Security-Policy');
        self::assertStringStartsWith("default-src 'none'", $policy);
        self::assertStringContainsString("form-action 'self' https://client.test;", $policy);
        self::assertSame('no-store', $page->getHeaderLine('Cache-Control'));
        // Nothing about the request travels through the page but the handle.
        self::assertStringNotContainsString(self::TEST_REDIRECT_URI, $body);
    }

    public function testAFirstPartyApplicationAsksWhenTheApiForbidsSkipping(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $this->invoicesApi(allowSkippingConsent: false);

        $state = $this->consentState(
            $this->authorize(['scope' => 'openid invoices:read', 'audience' => self::INVOICES]),
        );
        $body = (string) $this->get('/auth/consent', ['state' => $state])->getBody();

        self::assertStringContainsString('Invoices', $body);
        self::assertStringContainsString('Read your invoices', $body);
        self::assertStringContainsString('invoices:read', $body);
    }

    public function testAFirstPartyApplicationSkipsWhenTheApiAllowsIt(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $this->invoicesApi(allowSkippingConsent: true);

        $response = $this->authorize(['scope' => 'openid invoices:read', 'audience' => self::INVOICES]);

        self::assertArrayHasKey('code', self::locationQuery($response));
    }

    public function testPromptConsentAsksEvenAFirstPartyApplication(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $state = $this->consentState($this->authorize(['prompt' => 'consent']));

        $allowed = $this->decide($state, 'allow');

        // Back to the authorization request — minus the `consent` it asked for, which has
        // now been given, so the request does not loop back here forever.
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $allowed->getStatusCode());
        $location = $allowed->getHeaderLine('Location');
        self::assertStringStartsWith('/oauth2/authorize?', $location);
        self::assertStringNotContainsString('prompt', $location);
        self::assertArrayHasKey('code', self::locationQuery($this->get($location)));
    }

    public function testPromptNoneCannotAskAndSaysSo(): void
    {
        // OIDC Core §3.1.2.6: `prompt=none` with consent outstanding is `consent_required`.
        $this->loggedIn();
        $this->thirdPartyClient();

        $response = $this->asThirdParty(overrides: ['prompt' => 'none']);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        $query = self::locationQuery($response);
        self::assertSame('consent_required', $query['error']);
        self::assertSame('test-state-value', $query['state']);
    }

    public function testPromptNoneWithNobodySignedInIsLoginRequired(): void
    {
        $this->publicClient();

        $response = $this->authorize(['prompt' => 'none']);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        self::assertSame('login_required', self::locationQuery($response)['error']);
    }

    // ── The decision ────────────────────────────────────────────────────────────

    public function testAllowingRecordsTheConsentAndIssuesTheCode(): void
    {
        $user = $this->loggedIn();
        $this->thirdPartyClient();
        $state = $this->consentState($this->asThirdParty('openid email'));

        $allowed = $this->decide($state, 'allow');

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $allowed->getStatusCode());
        $this->extractCode($this->get($allowed->getHeaderLine('Location')));
        $consents = $this->storedConsents();
        self::assertCount(1, $consents);
        self::assertSame($user->id->value, $consents[0]['user_id']);
        self::assertSame(self::THIRD_PARTY_CLIENT_ID, $consents[0]['client_id']);
        self::assertNull($consents[0]['resource_server_id']);
        self::assertSame('openid email', $consents[0]['scope']);
        // The handle was spent by the decision.
        self::assertSame(
            StatusCodeInterface::STATUS_BAD_REQUEST,
            $this->get('/auth/consent', ['state' => $state])->getStatusCode(),
        );
    }

    public function testARecordedConsentIsNotAskedForAgain(): void
    {
        $this->loggedIn();
        $this->thirdPartyClient();
        $this->decide(
            $this->consentState($this->asThirdParty('openid email')),
            'allow',
        );

        // The same, and less: both covered.
        foreach (['openid email', 'openid'] as $scope) {
            $response = $this->authorize(['client_id' => self::THIRD_PARTY_CLIENT_ID, 'scope' => $scope]);
            self::assertArrayHasKey('code', self::locationQuery($response), $scope);
        }
    }

    public function testAskingForMoreAsksAgainAndWidensTheRecord(): void
    {
        $this->loggedIn();
        $this->thirdPartyClient();
        $this->decide(
            $this->consentState($this->asThirdParty('openid')),
            'allow',
        );

        $state = $this->consentState(
            $this->asThirdParty('openid profile'),
        );
        $this->decide($state, 'allow');

        $consents = $this->storedConsents();
        self::assertCount(1, $consents);
        self::assertSame('openid profile', $consents[0]['scope']);
    }

    public function testRefusingSendsAccessDeniedToTheApplication(): void
    {
        $this->loggedIn();
        $this->thirdPartyClient();
        $state = $this->consentState($this->asThirdParty());

        $refused = $this->decide($state, 'deny');

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $refused->getStatusCode());
        self::assertStringStartsWith(self::TEST_REDIRECT_URI . '?', $refused->getHeaderLine('Location'));
        $query = self::locationQuery($refused);
        self::assertSame('access_denied', $query['error']);
        self::assertSame('test-state-value', $query['state']);
        self::assertArrayHasKey('iss', $query);
        self::assertSame([], $this->storedConsents());
    }

    public function testConsentOnOneApiSaysNothingAboutAnother(): void
    {
        // `invoices:read` here is not `invoices:read` there.
        $this->loggedIn();
        $this->thirdPartyClient();
        $this->invoicesApi(allowSkippingConsent: true);
        $this->anApi('https://other.test/', ['invoices:read']);
        $this->decide($this->consentState($this->authorize([
            'client_id' => self::THIRD_PARTY_CLIENT_ID,
            'scope' => 'openid invoices:read',
            'audience' => self::INVOICES,
        ])), 'allow');

        $response = $this->authorize([
            'client_id' => self::THIRD_PARTY_CLIENT_ID,
            'scope' => 'openid invoices:read',
            'audience' => 'https://other.test/',
        ]);

        $this->consentState($response);
    }

    public function testAPostedAuthorizationRequestIsResumedWhole(): void
    {
        // The request is resumed by a GET carrying every parameter, whichever method
        // brought it: one posted to the endpoint is not lost on the way to the screen.
        $this->loggedIn();
        $this->thirdPartyClient();
        [, $challenge] = $this->makePkcePair();
        $state = $this->consentState($this->post(
            '/oauth2/authorize',
            $this->authorizeParams($challenge, ['client_id' => self::THIRD_PARTY_CLIENT_ID]),
        ));

        $allowed = $this->decide($state, 'allow');

        $this->extractCode($this->get($allowed->getHeaderLine('Location')));
    }

    // ── The screen's own defences ───────────────────────────────────────────────

    public function testTheScreenIsBoundToThePersonWhoWasAsked(): void
    {
        $this->loggedIn();
        $this->thirdPartyClient();
        $state = $this->consentState($this->asThirdParty());
        $this->container()->get(UserRepository::class)->save(User::register(
            UserId::generate($this->container()->get(RandomSource::class)),
            'else@clavia.dev',
            null,
            $this->container()->get(Clock::class)->now(),
        ));
        $this->boot(['CLAVIA_DEV_AUTOLOGIN_EMAIL' => 'else@clavia.dev']);

        $page = $this->get('/auth/consent', ['state' => $state]);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $page->getStatusCode());
        self::assertStringContainsString('expired', strtolower((string) $page->getBody()));
        self::assertStringNotContainsString('Partner Analytics', (string) $page->getBody());
    }

    public function testTheScreenNeedsASignedInPerson(): void
    {
        $response = $this->get('/auth/consent', ['state' => 'anything']);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertStringStartsWith('/auth/login?state=', $response->getHeaderLine('Location'));
        // And comes back to the same screen afterwards.
        self::assertSame(
            '/auth/consent?state=anything',
            $this->loginState(self::locationQuery($response)['state'])?->nextUrl,
        );
    }

    public function testAWrongCsrfTokenReRendersWithoutDeciding(): void
    {
        $this->loggedIn();
        $this->thirdPartyClient();
        $state = $this->consentState($this->asThirdParty());

        $response = $this->decide($state, 'allow', csrfToken: 'forged');

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame([], $this->storedConsents());
        // Still on hold: only the click is lost.
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->decide($state, 'allow')->getStatusCode());
    }

    public function testAnUnknownHandleIsAnExpiredRequest(): void
    {
        $this->loggedIn();

        $page = $this->get('/auth/consent', ['state' => 'never-issued']);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $page->getStatusCode());
        self::assertStringContainsString('expired', strtolower((string) $page->getBody()));
    }

    // ── What a third-party application can never do ─────────────────────────────

    public function testAThirdPartyApplicationCannotAskAPersonForTheManagementApi(): void
    {
        $this->loggedIn();
        $this->thirdPartyClient();
        $this->managementApi();

        $response = $this->authorize([
            'client_id' => self::THIRD_PARTY_CLIENT_ID,
            'scope' => 'openid read:users',
            'audience' => self::MANAGEMENT_API,
        ]);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        $query = self::locationQuery($response);
        self::assertSame('access_denied', $query['error']);
        self::assertSame('test-state-value', $query['state']);
    }

    public function testAThirdPartyMachineCannotBeGrantedTheManagementApi(): void
    {
        $api = $this->managementApi();
        $outsider = $this->thirdPartyMachine();

        try {
            $this->container()->get(GrantClientAccess::class)(
                $outsider->id,
                $api->identifier,
                ScopeSet::fromString('read:users'),
            );
            self::fail('A third-party machine was granted the Management API.');
        } catch (InvalidValue $refusal) {
            self::assertStringContainsString('third-party', $refusal->getMessage());
        }

        // Even a grant that bypassed the command mints nothing.
        $this->container()->get(ClientGrantRepository::class)->save(ClientGrant::grant(
            $outsider->id,
            $api,
            ScopeSet::fromString('read:users'),
            new DateTimeImmutable(),
        ));
        $response = $this->post(
            '/oauth2/token',
            ['grant_type' => 'client_credentials', 'audience' => self::MANAGEMENT_API],
            basicAuth: ['tpc_test-machine', self::TEST_M2M_SECRET],
        );

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('access_denied', self::json($response)['error']);
    }

    public function testAFirstPartyMachineIsUnaffected(): void
    {
        $api = $this->managementApi();
        $client = $this->m2mClient();
        $grant = $this->container()->get(GrantClientAccess::class);
        $grant($client->id, $api->identifier, ScopeSet::fromString('read:users'));

        $response = $this->requestMachineToken(['audience' => self::MANAGEMENT_API]);

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
    }

    // ── Registration and administration ─────────────────────────────────────────

    public function testOwnershipIsSetAtCreationAndNeverChanged(): void
    {
        $this->adminToken();

        $created = $this->api('POST', '/api/v1/clients', [
            'name' => 'Partner',
            'client_type' => 'public',
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'redirect_uris' => ['https://partner.test/callback'],
            'is_first_party' => false,
        ]);
        self::assertSame(StatusCodeInterface::STATUS_CREATED, $created->getStatusCode(), (string) $created->getBody());
        $body = self::document($created);
        self::assertFalse($body['is_first_party']);
        self::assertMatchesRegularExpression('/^tpc_[A-Za-z0-9]{32}$/D', (string) $body['client_id']);

        // Identity, not configuration: the contract has no such field on an update.
        $path = '/api/v1/clients/' . (string) $body['client_id'];
        self::assertSame(
            StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
            $this->api('PATCH', $path, ['is_first_party' => true])->getStatusCode(),
        );
        self::assertFalse(self::document($this->api('GET', $path))['is_first_party']);
    }

    public function testTheDefaultRegistrationIsFirstParty(): void
    {
        $this->adminToken();

        $created = self::document($this->api('POST', '/api/v1/clients', [
            'client_type' => 'public',
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'redirect_uris' => ['https://a.test/cb'],
        ]));

        self::assertTrue($created['is_first_party']);
        self::assertStringStartsNotWith('tpc_', (string) $created['client_id']);
    }

    public function testConsentsAreListedAndCanBeWithdrawn(): void
    {
        $user = $this->loggedIn();
        $this->thirdPartyClient();
        $this->decide(
            $this->consentState($this->asThirdParty('openid email')),
            'allow',
        );
        $this->adminToken();
        $consents = '/api/v1/users/' . $user->id->value . '/consents';

        $listed = $this->api('GET', $consents);

        self::assertSame(StatusCodeInterface::STATUS_OK, $listed->getStatusCode(), (string) $listed->getBody());
        $document = self::document($listed);
        self::assertCount(1, $document);
        self::assertIsArray($document[0]);
        self::assertSame(self::THIRD_PARTY_CLIENT_ID, $document[0]['client_id']);
        self::assertSame('Partner Analytics', $document[0]['client_name']);
        self::assertFalse($document[0]['is_first_party']);
        self::assertNull($document[0]['audience']);
        self::assertSame(['email', 'openid'], $document[0]['scopes']);

        self::assertSame(
            StatusCodeInterface::STATUS_NO_CONTENT,
            $this->api('DELETE', $consents . '/' . self::THIRD_PARTY_CLIENT_ID)->getStatusCode(),
        );
        self::assertSame(
            StatusCodeInterface::STATUS_NO_CONTENT,
            $this->api('DELETE', $consents . '/' . self::THIRD_PARTY_CLIENT_ID)->getStatusCode(),
        );
        self::assertSame([], self::document($this->api('GET', $consents)));
        // Withdrawn: the application has to ask again.
        $this->consentState($this->asThirdParty('openid email'));
    }

    public function testConsentsOfAnUnknownUserAreNotFound(): void
    {
        $this->adminToken();
        $unknown = '/api/v1/users/00000000-0000-4000-8000-000000000999/consents';

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->api('GET', $unknown)->getStatusCode());
        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->api('DELETE', $unknown . '/spa')->getStatusCode(),
        );
    }

    public function testAnApiCanStopFirstPartyApplicationsSkippingConsent(): void
    {
        $this->adminToken();

        $created = $this->api('POST', '/api/v1/resource-servers', [
            'identifier' => 'https://strict.test/',
            'name' => 'Strict',
            'allow_skipping_consent' => false,
        ]);
        self::assertSame(StatusCodeInterface::STATUS_CREATED, $created->getStatusCode(), (string) $created->getBody());
        self::assertFalse(self::document($created)['allow_skipping_consent']);

        $patched = $this->api(
            'PATCH',
            '/api/v1/resource-servers/' . (string) self::document($created)['id'],
            ['allow_skipping_consent' => true],
        );
        self::assertTrue(self::document($patched)['allow_skipping_consent']);
    }

    public function testTheManagementApiNeverAsksForConsent(): void
    {
        $this->adminToken();
        $id = $this->managementApi()->id->value;

        $response = $this->api('PATCH', '/api/v1/resource-servers/' . $id, ['allow_skipping_consent' => false]);

        self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $response->getStatusCode());
        $read = self::document($this->api('GET', '/api/v1/resource-servers/' . $id));
        self::assertTrue($read['allow_skipping_consent']);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private function thirdPartyClient(): Client
    {
        $client = Client::register(
            ClientId::fromString(self::THIRD_PARTY_CLIENT_ID),
            'Partner Analytics',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString(self::TEST_REDIRECT_URI)],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            $this->container()->get(Clock::class)->now(),
        );
        $this->container()->get(ClientRepository::class)->save($client);

        return $client;
    }

    private function thirdPartyMachine(): Client
    {
        $client = Client::register(
            ClientId::fromString('tpc_test-machine'),
            'Partner machine',
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretBasic,
            $this->container()->get(PasswordHasher::class)->hash(self::TEST_M2M_SECRET),
            [],
            [GrantType::ClientCredentials],
            [],
            $this->container()->get(Clock::class)->now(),
        );
        $this->container()->get(ClientRepository::class)->save($client);

        return $client;
    }

    private function invoicesApi(bool $allowSkippingConsent): ResourceServer
    {
        $api = ResourceServer::register(
            ResourceServerId::fromString('rs_' . substr(hash('sha256', self::INVOICES), 0, 16)),
            Audience::fromString(self::INVOICES),
            'Invoices',
            [Permission::of('invoices:read', 'Read your invoices')],
            $this->container()->get(Clock::class)->now(),
            allowSkippingConsent: $allowSkippingConsent,
        );
        $this->container()->get(ResourceServerRepository::class)->save($api);

        return $api;
    }

    /**
     * The third-party application's authorization request.
     *
     * @param array<string, string|null> $overrides
     */
    private function asThirdParty(string $scope = 'openid profile', array $overrides = []): ResponseInterface
    {
        return $this->authorize(['client_id' => self::THIRD_PARTY_CLIENT_ID, 'scope' => $scope] + $overrides);
    }

    /**
     * @param array<string, string|null> $overrides
     */
    private function authorize(array $overrides = []): ResponseInterface
    {
        [, $challenge] = $this->makePkcePair();

        return $this->get('/oauth2/authorize', $this->authorizeParams($challenge, $overrides));
    }

    /** The handle `/oauth2/authorize` sent the browser to the consent screen with. */
    private function consentState(ResponseInterface $response): string
    {
        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $response->getStatusCode(),
            $response->getHeaderLine('Location'),
        );
        $location = $response->getHeaderLine('Location');
        self::assertStringStartsWith('/auth/consent?state=', $location);

        return self::locationQuery($response)['state'];
    }

    /** Load the screen, for its CSRF token, and press one of its two buttons. */
    private function decide(string $state, string $decision, ?string $csrfToken = null): ResponseInterface
    {
        $page = $this->get('/auth/consent', ['state' => $state]);
        self::assertSame(StatusCodeInterface::STATUS_OK, $page->getStatusCode(), (string) $page->getBody());

        return $this->post('/auth/consent', [
            'csrf_token' => $csrfToken ?? self::csrfTokenFrom($page),
            'state' => $state,
            'decision' => $decision,
        ]);
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function storedConsents(): array
    {
        /** @var list<array<string, mixed>> */
        return TestStorage::database()->fetchAll('SELECT * FROM user_consents ORDER BY granted_at');
    }
}
