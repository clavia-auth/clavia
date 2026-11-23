<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\OAuth2;

use ClaviaTest\Support\Fake\FakeDpopProofVerifier;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAttemptCounter;
use ClaviaTest\Support\Fake\InMemoryDpopNonces;
use ClaviaTest\Support\Fake\InMemoryDpopReplayCache;
use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\ClientAuthentication\ClientFailureThrottle;
use Clavia\Application\OAuth2\ClientAuthentication\TooManyFailedRequests;
use Clavia\Application\OAuth2\Dpop\ReadDpopProof;
use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Application\OAuth2\Token\Grant;
use Clavia\Application\OAuth2\Token\IssuedToken;
use Clavia\Application\OAuth2\Token\IssueToken;
use Clavia\Application\OAuth2\Token\TokenRequest;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\OAuth2\Dpop\JwkThumbprint;
use Clavia\Domain\OAuth2\ErrorCode;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use PHPUnit\Framework\TestCase;

final class IssueTokenTest extends TestCase
{
    private InMemoryClientRepository $clients;
    private const string ADDRESS = '203.0.113.7';

    private const string TOKEN_ENDPOINT = 'https://auth.clavia.test/oauth2/token';

    private ClientAuthenticator $authenticator;
    private ClientFailureThrottle $throttle;
    private ReadDpopProof $dpop;

    /** @var list<string> The ids of the clients the grant was asked to issue for. */
    private array $issuedFor = [];

    #[\Override]
    protected function setUp(): void
    {
        $this->clients = new InMemoryClientRepository();
        $this->clients->save(Clients::public('spa'));
        $this->clients->save(Clients::public('no-grant', grantTypes: [], responseTypes: []));
        $this->throttle = new ClientFailureThrottle(new InMemoryAttemptCounter(new FrozenClock()), 1000, 300);
        $clock = new FrozenClock();
        $this->dpop = new ReadDpopProof(
            new FakeDpopProofVerifier(),
            new InMemoryDpopReplayCache($clock),
            new InMemoryDpopNonces($clock),
            $clock,
            60,
        );
        $this->authenticator = new ClientAuthenticator($this->clients, new FakePasswordHasher(), $this->throttle);
    }

    public function testAnAuthenticatedClientIsHandedToTheGrantItAskedFor(): void
    {
        $token = $this->issue(['grant_type' => 'authorization_code', 'client_id' => 'spa', 'code' => 'abc']);

        self::assertSame('minted', $token->accessToken);
        self::assertSame(['spa'], $this->issuedFor);
    }

    public function testARepeatedParameterIsRefusedBeforeAnythingElse(): void
    {
        $issueToken = $this->issuer($this->aGrant());

        $error = $this->refusal(static fn (): IssuedToken => $issueToken(new TokenRequest(
            new RequestParameters(['grant_type' => ['authorization_code'], 'code' => ['one', 'two']]),
            null,
            self::ADDRESS,
        )));

        self::assertSame(ErrorCode::InvalidRequest, $error->error);
        self::assertStringContainsString("'code'", $error->description);
    }

    public function testAMissingGrantTypeIsAnInvalidRequest(): void
    {
        $error = $this->refusal(fn (): IssuedToken => $this->issue(['client_id' => 'spa']));

        self::assertSame(ErrorCode::InvalidRequest, $error->error);
    }

    public function testAnUnknownGrantTypeIsUnsupported(): void
    {
        $error = $this->refusal(fn (): IssuedToken => $this->issue(['grant_type' => 'password', 'client_id' => 'spa']));

        self::assertSame(ErrorCode::UnsupportedGrantType, $error->error);
        self::assertSame([], $this->issuedFor);
    }

    public function testAKnownGrantTypeTheServerDoesNotOfferIsUnsupported(): void
    {
        $withoutGrants = new IssueToken($this->authenticator, $this->throttle, $this->dpop, self::TOKEN_ENDPOINT);

        $error = $this->refusal(static fn (): IssuedToken => $withoutGrants(new TokenRequest(
            RequestParameters::fromMap(['grant_type' => 'authorization_code', 'client_id' => 'spa']),
            null,
            self::ADDRESS,
        )));

        self::assertSame(ErrorCode::UnsupportedGrantType, $error->error);
    }

    public function testAClientThatCannotAuthenticateNeverReachesTheGrant(): void
    {
        $error = $this->refusal(
            fn (): IssuedToken => $this->issue(['grant_type' => 'authorization_code', 'client_id' => 'nobody']),
        );

        self::assertSame(ErrorCode::InvalidClient, $error->error);
        self::assertSame([], $this->issuedFor);
    }

    public function testAuthenticatingIsNotBeingRegisteredForAGrant(): void
    {
        $error = $this->refusal(
            fn (): IssuedToken => $this->issue(['grant_type' => 'authorization_code', 'client_id' => 'no-grant']),
        );

        self::assertSame(ErrorCode::UnauthorizedClient, $error->error);
        self::assertSame([], $this->issuedFor);
    }

    public function testOnlyTheMethodsTheGrantAcceptsAreTried(): void
    {
        $issueToken = new IssueToken(
            $this->authenticator,
            $this->throttle,
            $this->dpop,
            self::TOKEN_ENDPOINT,
            $this->aGrant([ClientAuthMethod::ClientSecretBasic]),
        );

        $error = $this->refusal(static fn (): IssuedToken => $issueToken(new TokenRequest(
            RequestParameters::fromMap(['grant_type' => 'authorization_code', 'client_id' => 'spa']),
            null,
            self::ADDRESS,
        )));

        self::assertSame(ErrorCode::InvalidClient, $error->error);
    }

    private function issuer(Grant ...$grants): IssueToken
    {
        return new IssueToken($this->authenticator, $this->throttle, $this->dpop, self::TOKEN_ENDPOINT, ...$grants);
    }

    /**
     * @param array<string, string> $form
     */
    private function issue(array $form): IssuedToken
    {
        return $this->issuer($this->aGrant())(
            new TokenRequest(RequestParameters::fromMap($form), null, self::ADDRESS),
        );
    }

    /**
     * @param callable(): IssuedToken $work
     */
    private function refusal(callable $work): OAuth2Error
    {
        try {
            $work();
        } catch (OAuth2Error $error) {
            return $error;
        }

        self::fail('A token was issued.');
    }

    public function testItSaysWhichGrantsItAnswersAndHowClientsMayAuthenticateForThem(): void
    {
        $issueToken = new IssueToken(
            $this->authenticator,
            $this->throttle,
            $this->dpop,
            self::TOKEN_ENDPOINT,
            $this->aGrant([ClientAuthMethod::ClientSecretBasic, ClientAuthMethod::None]),
        );

        self::assertSame([GrantType::AuthorizationCode], $issueToken->supportedGrantTypes());
        self::assertSame(
            [ClientAuthMethod::ClientSecretBasic, ClientAuthMethod::None],
            $issueToken->supportedAuthMethods(),
        );
        self::assertSame([], $this->issuer()->supportedGrantTypes());
    }

    public function testARejectedGrantCountsAndAPendingDeviceDoesNot(): void
    {
        // RFC 8628 §3.5: a device told to keep polling is doing what it was told.
        $hasher = new FakePasswordHasher();
        $this->clients->save(Clients::confidential('backend', $hasher->hash('s3cret')));
        $throttle = new ClientFailureThrottle(new InMemoryAttemptCounter(new FrozenClock()), 2, 300);
        $authenticator = new ClientAuthenticator($this->clients, $hasher, $throttle);
        $request = new TokenRequest(
            RequestParameters::fromMap(['grant_type' => 'authorization_code']),
            'Basic ' . base64_encode('backend:s3cret'),
            self::ADDRESS,
        );
        $pendingGrant = $this->failingGrant(OAuth2Error::authorizationPending('Wait.'));
        $pending = new IssueToken($authenticator, $throttle, $this->dpop, self::TOKEN_ENDPOINT, $pendingGrant);
        $rejected = new IssueToken(
            $authenticator,
            $throttle,
            $this->dpop,
            self::TOKEN_ENDPOINT,
            $this->failingGrant(OAuth2Error::invalidGrant('No.')),
        );

        for ($i = 0; $i < 5; ++$i) {
            $error = $this->refusal(static fn (): IssuedToken => $pending($request));
            self::assertSame(ErrorCode::AuthorizationPending, $error->error);
        }
        $this->refusal(static fn (): IssuedToken => $rejected($request));
        $this->refusal(static fn (): IssuedToken => $rejected($request));

        $this->expectException(TooManyFailedRequests::class);
        $pending($request);
    }

    /** A grant for confidential clients that always answers with the error given. */
    private function failingGrant(OAuth2Error $error): Grant
    {
        return new readonly class ($error) implements Grant {
            public function __construct(private OAuth2Error $error)
            {
            }

            #[\Override]
            public function type(): GrantType
            {
                return GrantType::AuthorizationCode;
            }

            #[\Override]
            public function acceptedAuthMethods(): array
            {
                return [ClientAuthMethod::ClientSecretBasic];
            }

            #[\Override]
            public function issue(
                RequestParameters $parameters,
                Client $client,
                ?JwkThumbprint $dpopKey = null,
            ): IssuedToken {
                throw $this->error;
            }
        };
    }

    /**
     * A grant that records who it issued for.
     *
     * @param list<ClientAuthMethod> $accepted
     */
    private function aGrant(array $accepted = [ClientAuthMethod::None]): Grant
    {
        $record = function (Client $client): void {
            $this->issuedFor[] = $client->id->value;
        };

        return new readonly class ($accepted, $record(...)) implements Grant {
            /**
             * @param list<ClientAuthMethod> $accepted
             * @param \Closure(Client): void $record
             */
            public function __construct(private array $accepted, private \Closure $record)
            {
            }

            #[\Override]
            public function type(): GrantType
            {
                return GrantType::AuthorizationCode;
            }

            #[\Override]
            public function acceptedAuthMethods(): array
            {
                return $this->accepted;
            }

            #[\Override]
            public function issue(
                RequestParameters $parameters,
                Client $client,
                ?JwkThumbprint $dpopKey = null,
            ): IssuedToken {
                ($this->record)($client);

                return new IssuedToken('minted', 'Bearer', 3600, ScopeSet::empty());
            }
        };
    }
}
