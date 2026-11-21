<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\OAuth2;

use Clavia\Application\Authentication\EndUser;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\OAuth2\Authorize\AuthorizationOutcome;
use Clavia\Application\OAuth2\Authorize\AuthorizationRequest;
use Clavia\Application\OAuth2\Authorize\Authorize;
use Clavia\Application\OAuth2\Authorize\CodeIssued;
use Clavia\Application\OAuth2\Authorize\ConsentRequired;
use Clavia\Application\OAuth2\Authorize\LoginRequired;
use Clavia\Application\OAuth2\Authorize\RequestRefused;
use Clavia\Application\OAuth2\ReadRequestedAccess;
use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Application\Port\NonceRegistry;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Consent\UserConsent;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\ErrorCode;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FakeIdentityProviders;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAuthorizationCodeRepository;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryConnectionRepository;
use ClaviaTest\Support\Fake\InMemoryConsentRepository;
use ClaviaTest\Support\Fake\InMemoryConsentStateStore;
use ClaviaTest\Support\Fake\InMemoryLoginStateStore;
use ClaviaTest\Support\Fake\InMemoryNonceRegistry;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryRoleRepository;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\RecordingMailer;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AuthorizeTest extends TestCase
{
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    private const string ENDPOINT = '/oauth2/authorize';

    private InMemoryClientRepository $clients;
    private InMemoryAuthorizationCodeRepository $codes;
    private InMemoryLoginStateStore $loginStates;
    private InMemoryNonceRegistry $nonces;
    private InMemoryResourceServerRepository $resourceServers;
    private InMemoryRoleRepository $roles;
    private InMemoryConsentRepository $consents;
    private InMemoryConsentStateStore $consentStates;
    private InMemoryConnectionRepository $connections;
    private Authorize $authorize;
    private UserId $userId;
    private Sessions $sessions;

    #[\Override]
    protected function setUp(): void
    {
        $clock = new FrozenClock('2026-01-15T10:00:00Z');
        $random = new SeededRandomSource(1);
        $this->clients = new InMemoryClientRepository();
        $this->codes = new InMemoryAuthorizationCodeRepository();
        $this->loginStates = new InMemoryLoginStateStore($clock);
        $this->nonces = new InMemoryNonceRegistry($clock);
        $this->resourceServers = new InMemoryResourceServerRepository();
        $this->roles = new InMemoryRoleRepository($this->resourceServers);
        $this->consents = new InMemoryConsentRepository();
        $this->consentStates = new InMemoryConsentStateStore($clock);
        $this->connections = new InMemoryConnectionRepository($this->clients);
        $this->userId = UserId::generate(new SeededRandomSource(2));
        $this->sessions = new Sessions(
            new InMemorySessionStore($clock),
            new SecretGenerator(new SeededRandomSource(3)),
            $clock,
            28800,
            604800,
        );
        $this->authorize = new Authorize(
            $this->clients,
            $this->codes,
            $this->loginStates,
            $this->nonces,
            new ReadRequestedAccess($this->resourceServers, ScopeSet::fromString('openid profile email')),
            $this->roles,
            $this->consents,
            $this->consentStates,
            new ConnectionAccess($this->connections, new FakeIdentityProviders(), new RecordingMailer(false)),
            $this->sessions,
            new SecretGenerator($random),
            $random,
            $clock,
            60,
            360,
        );

        $this->clients->save(Clients::public('spa'));
    }

    // ── A code is issued ────────────────────────────────────────────────────────

    public function testASignedInUserGetsACodeSentToTheRegisteredRedirectUri(): void
    {
        $outcome = $this->authorizeAsUser($this->valid());

        self::assertInstanceOf(CodeIssued::class, $outcome);
        self::assertSame(Clients::REDIRECT_URI, $outcome->redirectUri);
        self::assertSame('xyz', $outcome->state);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $outcome->code);
    }

    public function testTheCodeIsStoredAsADigestBoundToEverythingTheTokenEndpointWillCheck(): void
    {
        $outcome = $this->authorizeAsUser($this->valid(['scope' => 'openid email']));

        self::assertInstanceOf(CodeIssued::class, $outcome);
        self::assertCount(1, $this->codes->all());
        $stored = $this->codes->all()[0];
        self::assertTrue($stored->digest->equals(Digest::of($outcome->code)));
        self::assertSame('spa', $stored->clientId->value);
        self::assertTrue($stored->userId->equals($this->userId));
        self::assertSame(Clients::REDIRECT_URI, $stored->redirectUri);
        self::assertSame('openid email', $stored->scope->toString());
        self::assertSame(self::CHALLENGE, $stored->challenge->value);
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:01:00Z'), $stored->expiresAt);
        self::assertNull($stored->usedAt());
    }

    public function testEachRequestGetsItsOwnCode(): void
    {
        $first = $this->authorizeAsUser($this->valid());
        $second = $this->authorizeAsUser($this->valid());

        self::assertInstanceOf(CodeIssued::class, $first);
        self::assertInstanceOf(CodeIssued::class, $second);
        self::assertNotSame($first->code, $second->code);
    }

    public function testStateIsOptionalAndScopeMayBeEmpty(): void
    {
        $outcome = $this->authorizeAsUser($this->valid(['state' => null, 'scope' => null]));

        self::assertInstanceOf(CodeIssued::class, $outcome);
        self::assertNull($outcome->state);
        self::assertTrue($this->codes->all()[0]->scope->isEmpty());
    }

    public function testTheRedirectUriMayBeOmittedWhenExactlyOneIsRegistered(): void
    {
        $outcome = $this->authorizeAsUser($this->valid(['redirect_uri' => null]));

        self::assertInstanceOf(CodeIssued::class, $outcome);
        self::assertSame(Clients::REDIRECT_URI, $outcome->redirectUri);
    }

    // ── Refused without redirecting: the redirect target itself is not established ──

    #[DataProvider('unidentifiedClients')]
    public function testARequestWhoseClientCannotBeIdentifiedIsNeverRedirected(array $overrides): void
    {
        $error = $this->refusedOutright($this->valid($overrides));

        self::assertSame(ErrorCode::InvalidClient, $error->error);
        self::assertSame([], $this->codes->all());
    }

    /** @return iterable<string, array{array<string, string|null>}> */
    public static function unidentifiedClients(): iterable
    {
        yield 'no client_id' => [['client_id' => null]];
        yield 'an unknown client' => [['client_id' => 'nobody']];
        yield 'a malformed client id' => [['client_id' => 'not a client id']];
        yield 'another case' => [['client_id' => 'SPA']];
    }

    public function testARepeatedClientIdIsNeverRedirected(): void
    {
        $parameters = new RequestParameters(['client_id' => ['spa', 'other']] + $this->asLists($this->valid()));

        self::assertSame(ErrorCode::InvalidClient, $this->refusedOutright($parameters)->error);
    }

    /**
     * The open-redirect guard: whatever else the request says, nothing is ever sent to a
     * URI the client did not register.
     */
    #[DataProvider('unregisteredRedirectUris')]
    public function testAnUnregisteredRedirectUriIsNeverRedirectedTo(string $redirectUri): void
    {
        $error = $this->refusedOutright($this->valid(['redirect_uri' => $redirectUri]));

        self::assertSame(ErrorCode::InvalidRequest, $error->error);
        self::assertStringNotContainsString($redirectUri, $error->description);
        self::assertSame([], $this->codes->all());
        self::assertSame(0, $this->loginStates->count());
    }

    /** @return iterable<string, array{string}> */
    public static function unregisteredRedirectUris(): iterable
    {
        yield 'another site' => ['https://evil.example/cb'];
        yield 'a longer path' => ['https://app.example/cb/../../evil'];
        yield 'a query added' => ['https://app.example/cb?x=1'];
        yield 'a trailing slash' => ['https://app.example/cb/'];
        yield 'another scheme' => ['http://app.example/cb'];
        yield 'userinfo' => ['https://app.example@evil.example/cb'];
        yield 'not a URL' => ['javascript:alert(1)'];
    }

    public function testAnInvalidRequestToAnUnregisteredRedirectUriIsStillNotRedirected(): void
    {
        // The redirect URI is settled before anything that would be reported through it.
        $error = $this->refusedOutright($this->valid([
            'redirect_uri' => 'https://evil.example/cb',
            'response_type' => 'token',
            'code_challenge' => null,
        ]));

        self::assertSame(ErrorCode::InvalidRequest, $error->error);
    }

    public function testARepeatedRedirectUriIsNeverRedirected(): void
    {
        $parameters = new RequestParameters(
            ['redirect_uri' => [Clients::REDIRECT_URI, 'https://evil.example/cb']] + $this->asLists($this->valid()),
        );

        self::assertSame(ErrorCode::InvalidRequest, $this->refusedOutright($parameters)->error);
    }

    public function testTheRedirectUriCannotBeOmittedWhenSeveralAreRegistered(): void
    {
        $this->clients->save(Clients::public('multi', [Clients::REDIRECT_URI, 'https://app.example/other']));

        $error = $this->refusedOutright($this->valid(['client_id' => 'multi', 'redirect_uri' => null]));

        self::assertSame(ErrorCode::InvalidRequest, $error->error);
    }

    // ── Refused by redirecting back to the client ───────────────────────────────

    /**
     * @param array<string, string|null> $overrides
     */
    #[DataProvider('refusals')]
    public function testAnInvalidRequestIsReportedToTheClientWithItsState(array $overrides, ErrorCode $expected): void
    {
        $outcome = $this->authorizeAsUser($this->valid($overrides));

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame($expected, $outcome->error->error);
        self::assertSame(Clients::REDIRECT_URI, $outcome->redirectUri);
        self::assertSame('xyz', $outcome->state);
        self::assertSame([], $this->codes->all());
    }

    /** @return iterable<string, array{array<string, string|null>, ErrorCode}> */
    public static function refusals(): iterable
    {
        yield 'no response_type' => [['response_type' => null], ErrorCode::InvalidRequest];
        yield 'the implicit grant' => [['response_type' => 'token'], ErrorCode::UnsupportedResponseType];
        yield 'a hybrid response type' => [['response_type' => 'code token'], ErrorCode::UnsupportedResponseType];
        yield 'response_type in another case' => [['response_type' => 'Code'], ErrorCode::UnsupportedResponseType];
        yield 'an unknown scope' => [['scope' => 'openid admin'], ErrorCode::InvalidScope];
        yield 'a malformed scope' => [['scope' => 'open"id'], ErrorCode::InvalidScope];
        yield 'no code_challenge' => [['code_challenge' => null], ErrorCode::InvalidRequest];
        yield 'no code_challenge_method' => [['code_challenge_method' => null], ErrorCode::InvalidRequest];
        yield 'the plain method' => [['code_challenge_method' => 'plain'], ErrorCode::InvalidRequest];
        yield 'the method in another case' => [['code_challenge_method' => 's256'], ErrorCode::InvalidRequest];
        yield 'a challenge that is too short' => [['code_challenge' => 'short'], ErrorCode::InvalidRequest];
        yield 'a challenge that is not base64url' => [
            ['code_challenge' => str_repeat('a', 42) . '+'],
            ErrorCode::InvalidRequest,
        ];
    }

    public function testAClientNotRegisteredForCodesIsRefused(): void
    {
        $this->clients->save(Clients::public('no-code', grantTypes: [], responseTypes: []));

        $outcome = $this->authorizeAsUser($this->valid(['client_id' => 'no-code']));

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame(ErrorCode::UnauthorizedClient, $outcome->error->error);
    }

    public function testAnyRepeatedParameterIsRefused(): void
    {
        $outcome = $this->authorizeAsUser(
            new RequestParameters(['scope' => ['openid', 'profile']] + $this->asLists($this->valid())),
        );

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame(ErrorCode::InvalidRequest, $outcome->error->error);
        self::assertStringContainsString("'scope'", $outcome->error->description);
        self::assertSame('xyz', $outcome->state);
    }

    public function testARepeatedStateIsRefusedAndNotEchoed(): void
    {
        $outcome = $this->authorizeAsUser(
            new RequestParameters(['state' => ['one', 'two']] + $this->asLists($this->valid())),
        );

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertNull($outcome->state);
    }

    // ── OpenID Connect: nonce and authentication ────────────────────────────────

    public function testTheCodeRemembersTheNonceAndHowThePersonAuthenticated(): void
    {
        $session = Session::establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            'the-sid',
            new DateTimeImmutable('2026-01-15T09:00:00Z'),
            86_400,
        );

        $outcome = ($this->authorize)(new AuthorizationRequest(
            $this->valid(['nonce' => 'n-0S6_WzA2Mj']),
            self::ENDPOINT,
            new EndUser($this->userId, $session),
        ));

        self::assertInstanceOf(CodeIssued::class, $outcome);
        $stored = $this->codes->all()[0];
        self::assertSame('n-0S6_WzA2Mj', $stored->nonce?->value);
        self::assertEquals(new DateTimeImmutable('2026-01-15T09:00:00Z'), $stored->authentication->authenticatedAt);
        self::assertSame(['pwd'], $stored->authentication->methodValues());
    }

    public function testWithoutASessionTheAuthenticationIsUnknown(): void
    {
        $this->authorizeAsUser($this->valid());

        $stored = $this->codes->all()[0];
        self::assertNull($stored->nonce);
        self::assertNull($stored->authentication->authenticatedAt);
        self::assertSame([], $stored->authentication->methods);
    }

    public function testANonceIsSpentWithTheCodeItCameWith(): void
    {
        $this->authorizeAsUser($this->valid(['nonce' => 'once']));

        self::assertTrue($this->nonces->isUsed(ClientId::fromString('spa'), Nonce::fromString('once')));
    }

    public function testAReplayedNonceIsReportedToTheClientAndMintsNothing(): void
    {
        $this->authorizeAsUser($this->valid(['nonce' => 'once']));

        $outcome = $this->authorizeAsUser($this->valid(['nonce' => 'once']));

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame(ErrorCode::InvalidRequest, $outcome->error->error);
        self::assertSame('xyz', $outcome->state);
        self::assertCount(1, $this->codes->all());
    }

    public function testANonceSpentInTheMeantimeStillMintsNothing(): void
    {
        // Validation saw it unused; a concurrent request spent it before this one got a code.
        $raced = new class implements NonceRegistry {
            #[\Override]
            public function isUsed(ClientId $client, Nonce $nonce): bool
            {
                return false;
            }

            #[\Override]
            public function claim(ClientId $client, Nonce $nonce, int $ttlSeconds): bool
            {
                return false;
            }
        };
        $random = new SeededRandomSource(9);
        $authorize = new Authorize(
            $this->clients,
            $this->codes,
            $this->loginStates,
            $raced,
            new ReadRequestedAccess($this->resourceServers, ScopeSet::fromString('openid')),
            $this->roles,
            $this->consents,
            $this->consentStates,
            new ConnectionAccess($this->connections, new FakeIdentityProviders(), new RecordingMailer(false)),
            $this->sessions,
            new SecretGenerator($random),
            $random,
            new FrozenClock(),
            60,
            360,
        );

        $outcome = $authorize(new AuthorizationRequest(
            $this->valid(['nonce' => 'once']),
            self::ENDPOINT,
            new EndUser($this->userId),
        ));

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame("The 'nonce' has already been used.", $outcome->error->description);
        self::assertSame([], $this->codes->all());
    }

    public function testAReplayedNonceIsRefusedBeforeAnyoneIsAskedToSignIn(): void
    {
        $this->authorizeAsUser($this->valid(['nonce' => 'once']));

        $outcome = ($this->authorize)(
            new AuthorizationRequest($this->valid(['nonce' => 'once']), self::ENDPOINT, null),
        );

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame(0, $this->loginStates->count());
    }

    public function testANonceOnlyMattersInAnOpenIdConnectRequest(): void
    {
        $first = $this->authorizeAsUser($this->valid(['scope' => 'profile', 'nonce' => 'once']));
        $second = $this->authorizeAsUser($this->valid(['scope' => 'profile', 'nonce' => 'once']));

        self::assertInstanceOf(CodeIssued::class, $first);
        self::assertInstanceOf(CodeIssued::class, $second);
        self::assertNull($this->codes->all()[0]->nonce);
    }

    public function testAMalformedNonceIsReportedToTheClient(): void
    {
        $outcome = $this->authorizeAsUser($this->valid(['nonce' => "two\nlines"]));

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame(ErrorCode::InvalidRequest, $outcome->error->error);
        self::assertSame("Invalid 'nonce'.", $outcome->error->description);
    }

    // ── Nobody is signed in ─────────────────────────────────────────────────────

    public function testWithoutAUserTheRequestIsParkedBehindAnOpaqueHandle(): void
    {
        $outcome = ($this->authorize)(new AuthorizationRequest($this->valid(), self::ENDPOINT, null));

        self::assertInstanceOf(LoginRequired::class, $outcome);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $outcome->loginState);
        $parked = $this->loginStates->get($outcome->loginState);
        self::assertNotNull($parked);
        // Every parameter, in the query: a request posted to the endpoint resumes whole.
        self::assertSame(self::ENDPOINT . '?' . $this->valid()->toQueryString(), $parked->nextUrl);
        self::assertSame('spa', $parked->clientId?->value);
        self::assertSame([], $this->codes->all());
    }

    public function testAnInvalidRequestIsRefusedBeforeAnyoneIsAskedToSignIn(): void
    {
        $outcome = ($this->authorize)(
            new AuthorizationRequest($this->valid(['code_challenge' => null]), self::ENDPOINT, null),
        );

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame(0, $this->loginStates->count());
    }

    public function testAnUnregisteredRedirectUriIsRefusedBeforeAnyoneIsAskedToSignIn(): void
    {
        try {
            ($this->authorize)(new AuthorizationRequest(
                $this->valid(['redirect_uri' => 'https://evil.example/cb']),
                self::ENDPOINT,
                null,
            ));
            self::fail('The request was accepted.');
        } catch (OAuth2Error) {
            self::assertSame(0, $this->loginStates->count());
        }
    }

    // ── Consent ─────────────────────────────────────────────────────────────────

    public function testAThirdPartyApplicationIsPutOnHoldForTheConsentScreen(): void
    {
        $this->clients->save(Clients::public('tpc_partner'));

        $outcome = $this->authorizeAsUser($this->valid(['client_id' => 'tpc_partner', 'prompt' => 'consent']));

        self::assertInstanceOf(ConsentRequired::class, $outcome);
        $held = $this->consentStates->find($outcome->consentState);
        self::assertNotNull($held);
        self::assertTrue($held->userId->equals($this->userId));
        self::assertSame('tpc_partner', $held->clientId->value);
        self::assertSame(Clients::REDIRECT_URI, $held->redirectUri);
        self::assertSame('xyz', $held->state);
        self::assertSame('openid', $held->scope->toString());
        self::assertNull($held->resourceServerId);
        // Back to the same request — without the `consent` it prompted for, or it would
        // ask forever.
        self::assertSame(
            self::ENDPOINT . '?' . $this->valid(['client_id' => 'tpc_partner'])->toQueryString(),
            $held->resumeAt,
        );
        self::assertSame([], $this->codes->all());
    }

    public function testAConsentOnRecordThatCoversTheRequestIssuesTheCode(): void
    {
        $this->clients->save(Clients::public('tpc_partner'));
        $this->consents->save(UserConsent::give(
            $this->userId,
            ClientId::fromString('tpc_partner'),
            null,
            ScopeSet::fromString('openid email'),
            new DateTimeImmutable('2026-01-15T09:00:00Z'),
        ));

        $outcome = $this->authorizeAsUser($this->valid(['client_id' => 'tpc_partner']));

        self::assertInstanceOf(CodeIssued::class, $outcome);
    }

    public function testPromptConsentPutsEvenAFirstPartyRequestOnHold(): void
    {
        $outcome = $this->authorizeAsUser($this->valid(['prompt' => 'consent']));

        self::assertInstanceOf(ConsentRequired::class, $outcome);
        self::assertSame(
            self::ENDPOINT . '?' . $this->valid()->toQueryString(),
            $this->consentStates->find($outcome->consentState)?->resumeAt,
        );
    }

    public function testPromptNoneCannotAskForConsent(): void
    {
        $this->clients->save(Clients::public('tpc_partner'));

        $outcome = $this->authorizeAsUser($this->valid(['client_id' => 'tpc_partner', 'prompt' => 'none']));

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame(ErrorCode::ConsentRequired, $outcome->error->error);
        self::assertSame('xyz', $outcome->state);
        self::assertSame(0, $this->consentStates->count());
    }

    public function testPromptNoneCannotAskAnyoneToSignIn(): void
    {
        $outcome = ($this->authorize)(
            new AuthorizationRequest($this->valid(['prompt' => 'none']), self::ENDPOINT, null),
        );

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame(ErrorCode::LoginRequired, $outcome->error->error);
        self::assertSame(0, $this->loginStates->count());
    }

    public function testPromptLoginSendsASignedInPersonToSignInAgainOnce(): void
    {
        $outcome = $this->authorizeAsUser($this->valid(['prompt' => 'login consent']));

        self::assertInstanceOf(LoginRequired::class, $outcome);
        $parked = $this->loginStates->get($outcome->loginState);
        self::assertNotNull($parked);
        // The sign-in is what `login` asked for: the request it resumes asks no more, and
        // keeps what else it asked.
        self::assertSame(
            self::ENDPOINT . '?' . $this->valid(['prompt' => 'consent'])->toQueryString(),
            $parked->nextUrl,
        );
    }

    public function testMaxAgeZeroIsDroppedFromTheResumedRequest(): void
    {
        $outcome = $this->authorizeAsUser($this->valid(['max_age' => '0']));

        self::assertInstanceOf(LoginRequired::class, $outcome);
        $parked = $this->loginStates->get($outcome->loginState);
        self::assertNotNull($parked);
        self::assertSame(self::ENDPOINT . '?' . $this->valid()->toQueryString(), $parked->nextUrl);
    }

    public function testRequestObjectsAreRefusedBeforeTheOtherParametersAreLookedAt(): void
    {
        // The parameters a request object carries need not be beside it.
        $byValue = $this->authorizeAsUser(RequestParameters::fromMap([
            'client_id' => 'spa',
            'redirect_uri' => Clients::REDIRECT_URI,
            'request' => 'e30',
        ]));
        $byReference = $this->authorizeAsUser($this->valid(['request_uri' => 'https://client.test/r']));

        self::assertInstanceOf(RequestRefused::class, $byValue);
        self::assertSame(ErrorCode::RequestNotSupported, $byValue->error->error);
        self::assertInstanceOf(RequestRefused::class, $byReference);
        self::assertSame(ErrorCode::RequestUriNotSupported, $byReference->error->error);
        self::assertSame([], $this->codes->all());
    }

    public function testPromptNoneWithAnotherValueIsRefused(): void
    {
        $outcome = $this->authorizeAsUser($this->valid(['prompt' => 'none consent']));

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame(ErrorCode::InvalidRequest, $outcome->error->error);
    }

    public function testAThirdPartyApplicationNeverReachesASystemApi(): void
    {
        $this->clients->save(Clients::public('tpc_partner'));
        $this->resourceServers->save(ResourceServer::register(
            ResourceServerId::fromString('rs_aaaaaaaaaaaaaaaa'),
            Audience::fromString('https://management.example/api/v1/'),
            'Management',
            [Permission::of('read:users')],
            new DateTimeImmutable('2026-01-15T09:00:00Z'),
            isSystem: true,
            enforcePolicies: true,
        ));

        // Refused before anyone is asked to sign in, let alone to consent.
        $outcome = ($this->authorize)(new AuthorizationRequest(
            $this->valid([
                'client_id' => 'tpc_partner',
                'scope' => 'openid read:users',
                'audience' => 'https://management.example/api/v1/',
            ]),
            self::ENDPOINT,
            null,
        ));

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame(ErrorCode::AccessDenied, $outcome->error->error);
        self::assertSame(0, $this->loginStates->count());
    }

    // ── Connections ─────────────────────────────────────────────────────────────

    public function testASessionThroughAConnectionTheApplicationDoesNotEnableCountsForNothing(): void
    {
        $this->clients->save(
            Clients::public('spa')->withConnections([ConnectionName::fromString('google')]),
        );

        $outcome = ($this->authorize)(new AuthorizationRequest(
            $this->valid(),
            self::ENDPOINT,
            new EndUser($this->userId, $this->sessionThrough(ConnectionName::defaultPool())),
        ));

        self::assertInstanceOf(LoginRequired::class, $outcome);
        self::assertSame([], $this->codes->all());
    }

    public function testASessionThroughAConnectionSwitchedOffSinceCountsForNothing(): void
    {
        $pool = $this->connections->find(ConnectionName::defaultPool());
        self::assertNotNull($pool);
        $this->connections->save($pool->switched(false, null, null));

        $outcome = ($this->authorize)(new AuthorizationRequest(
            $this->valid(['prompt' => 'none']),
            self::ENDPOINT,
            new EndUser($this->userId, $this->sessionThrough(ConnectionName::defaultPool())),
        ));

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame(ErrorCode::LoginRequired, $outcome->error->error);
    }

    public function testASessionThroughAConnectionTheApplicationEnablesIsUsed(): void
    {
        $outcome = ($this->authorize)(new AuthorizationRequest(
            $this->valid(),
            self::ENDPOINT,
            new EndUser($this->userId, $this->sessionThrough(ConnectionName::defaultPool())),
        ));

        self::assertInstanceOf(CodeIssued::class, $outcome);
    }

    public function testACodeIssuedThroughASessionCarriesItsSidAndTheSessionKnowsTheApplication(): void
    {
        $sessionId = $this->sessions->establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );
        $session = $this->sessions->resolve($sessionId);
        self::assertNotNull($session);

        $outcome = ($this->authorize)(
            new AuthorizationRequest($this->valid(), self::ENDPOINT, new EndUser($this->userId, $session)),
        );

        self::assertInstanceOf(CodeIssued::class, $outcome);
        self::assertSame($session->sid, $this->codes->all()[0]->authentication->sid);
        $clients = $this->sessions->resolve($sessionId)->clients ?? [];
        self::assertSame(['spa'], array_map(static fn (ClientId $id): string => $id->value, $clients));
    }

    public function testACodeWithoutASessionNamesNone(): void
    {
        self::assertInstanceOf(CodeIssued::class, $this->authorizeAsUser($this->valid()));
        self::assertNull($this->codes->all()[0]->authentication->sid);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private function sessionThrough(ConnectionName $connection): Session
    {
        return Session::establish(
            $this->userId,
            [AuthenticationMethod::Password],
            $connection,
            'the-sid',
            new DateTimeImmutable('2026-01-15T09:00:00Z'),
            86_400,
        );
    }

    /**
     * @param array<string, string|null> $overrides
     */
    private function valid(array $overrides = []): RequestParameters
    {
        return RequestParameters::fromMap(array_filter(
            $overrides + [
                'response_type' => 'code',
                'client_id' => 'spa',
                'redirect_uri' => Clients::REDIRECT_URI,
                'scope' => 'openid',
                'state' => 'xyz',
                'code_challenge' => self::CHALLENGE,
                'code_challenge_method' => 'S256',
            ],
            static fn (?string $value): bool => $value !== null,
        ));
    }

    /**
     * The same parameters in the shape that can express a repetition.
     *
     * @return array<string, list<string>>
     */
    private function asLists(RequestParameters $parameters): array
    {
        $names = [
            'response_type',
            'client_id',
            'redirect_uri',
            'scope',
            'state',
            'code_challenge',
            'code_challenge_method',
        ];
        $lists = [];
        foreach ($names as $name) {
            $value = $parameters->get($name);
            if ($value !== null) {
                $lists[$name] = [$value];
            }
        }

        return $lists;
    }

    private function authorizeAsUser(RequestParameters $parameters): AuthorizationOutcome
    {
        return ($this->authorize)(new AuthorizationRequest($parameters, self::ENDPOINT, new EndUser($this->userId)));
    }

    private function refusedOutright(RequestParameters $parameters): OAuth2Error
    {
        try {
            $this->authorizeAsUser($parameters);
        } catch (OAuth2Error $error) {
            return $error;
        }

        self::fail('The request was not refused outright.');
    }
}
