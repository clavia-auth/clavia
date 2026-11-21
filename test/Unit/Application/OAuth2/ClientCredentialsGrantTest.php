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
use Clavia\Application\OAuth2\Token\ClientCredentialsGrant;
use Clavia\Application\OAuth2\Token\IssuedToken;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\OAuth2\ErrorCode;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\ResourceServer\ClientGrant;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAccessTokenRepository;
use ClaviaTest\Support\Fake\InMemoryClientGrantRepository;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClientCredentialsGrantTest extends TestCase
{
    private const string AUDIENCE = 'https://invoices.example/api/';

    private FrozenClock $clock;
    private InMemoryResourceServerRepository $resourceServers;
    private InMemoryClientGrantRepository $clientGrants;
    private InMemoryAccessTokenRepository $tokens;
    private ClientCredentialsGrant $grant;
    private Client $client;
    private ResourceServer $api;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $random = new SeededRandomSource(1);
        $this->resourceServers = new InMemoryResourceServerRepository();
        $this->clientGrants = new InMemoryClientGrantRepository();
        $this->tokens = new InMemoryAccessTokenRepository();
        $this->grant = new ClientCredentialsGrant(
            $this->resourceServers,
            $this->clientGrants,
            $this->tokens,
            new SecretGenerator($random),
            $random,
            $this->clock,
            900,
        );

        $this->client = Clients::confidential('machine', '$hash$');
        $this->api = $this->api(self::AUDIENCE, ['invoices:read', 'invoices:write', 'invoices:delete']);
        $this->clientGrants->save(ClientGrant::grant(
            $this->client->id,
            $this->api,
            ScopeSet::fromString('invoices:read invoices:write'),
            $this->clock->now(),
        ));
    }

    public function testItIsTheClientCredentialsGrantAndOnlyForClientsWithASecret(): void
    {
        self::assertSame(GrantType::ClientCredentials, $this->grant->type());
        self::assertSame(
            [ClientAuthMethod::ClientSecretBasic, ClientAuthMethod::ClientSecretPost],
            $this->grant->acceptedAuthMethods(),
        );
    }

    public function testTheTokenIsTheClientsOwnForTheApiItNamed(): void
    {
        $issued = $this->issue();

        self::assertSame('Bearer', $issued->tokenType);
        self::assertSame(900, $issued->expiresIn);
        self::assertSame('invoices:read invoices:write', $issued->scope->toString());
        self::assertNull($issued->idToken);

        $stored = $this->tokens->all()[0];
        self::assertTrue($stored->digest->equals(Digest::of($issued->accessToken)));
        self::assertNull($stored->userId);
        self::assertNull($stored->authorizationCodeId);
        self::assertSame('machine', $stored->clientId->value);
        self::assertSame(self::AUDIENCE, $stored->audience?->value);
    }

    public function testANarrowerScopeIsWhatIsIssued(): void
    {
        self::assertSame('invoices:read', $this->issue(['scope' => 'invoices:read'])->scope->toString());
    }

    public function testAnEmptyScopeIsTheWholeGrant(): void
    {
        self::assertSame('invoices:read invoices:write', $this->issue(['scope' => ''])->scope->toString());
    }

    public function testAGrantHoldingNothingYieldsATokenCarryingNothing(): void
    {
        $this->clientGrants->save(
            ClientGrant::grant($this->client->id, $this->api, ScopeSet::empty(), $this->clock->now()),
        );

        self::assertTrue($this->issue()->scope->isEmpty());
    }

    public function testWhatTheApiNoLongerDefinesIsNoLongerIssued(): void
    {
        $this->resourceServers->save(ResourceServer::register(
            $this->api->id,
            $this->api->identifier,
            $this->api->name,
            [Permission::of('invoices:read')],
            $this->api->createdAt,
        ));

        self::assertSame('invoices:read', $this->issue()->scope->toString());
    }

    /**
     * @param array<string, string|null> $form
     */
    #[DataProvider('refusals')]
    public function testARefusalNamesWhatToFixAndIssuesNothing(array $form, ErrorCode $expected): void
    {
        try {
            $this->issue($form);
            self::fail('A token was issued.');
        } catch (OAuth2Error $error) {
            self::assertSame($expected, $error->error);
        }

        self::assertSame([], $this->tokens->all());
    }

    /** @return iterable<string, array{array<string, string|null>, ErrorCode}> */
    public static function refusals(): iterable
    {
        yield 'no audience' => [['audience' => null], ErrorCode::InvalidRequest];
        yield 'a malformed audience' => [['audience' => 'two words'], ErrorCode::InvalidRequest];
        yield 'an unknown API' => [['audience' => 'https://nowhere.example/'], ErrorCode::InvalidTarget];
        yield 'an API the client holds nothing on' => [
            ['audience' => 'https://other.example/api/'],
            ErrorCode::AccessDenied,
        ];
        yield 'a scope beyond the grant' => [['scope' => 'invoices:read invoices:delete'], ErrorCode::InvalidScope];
        yield 'a scope the API does not define' => [['scope' => 'profile'], ErrorCode::InvalidScope];
        yield 'a malformed scope' => [['scope' => 'invoices:"read"'], ErrorCode::InvalidScope];
        yield 'openid' => [['scope' => 'openid invoices:read'], ErrorCode::InvalidScope];
        // Refused before the audience is even looked at.
        yield 'openid without an audience' => [['scope' => 'openid', 'audience' => null], ErrorCode::InvalidScope];
    }

    /**
     * @param array<string, string|null> $form
     */
    private function issue(array $form = []): IssuedToken
    {
        $this->api('https://other.example/api/', ['other:read']);

        $parameters = array_filter(
            $form + ['grant_type' => 'client_credentials', 'audience' => self::AUDIENCE],
            static fn (?string $value): bool => $value !== null,
        );

        return $this->grant->issue(RequestParameters::fromMap($parameters), $this->client);
    }

    public function testAThirdPartyMachineGetsNoTokenForASystemApiWhateverItHolds(): void
    {
        $system = ResourceServer::register(
            ResourceServerId::fromString('rs_systemsystemsyst'),
            Audience::fromString('https://management.example/api/v1/'),
            'Management',
            [Permission::of('read:users')],
            $this->clock->now(),
            isSystem: true,
            enforcePolicies: true,
        );
        $this->resourceServers->save($system);
        $outsider = Clients::confidential('tpc_machine', '$hash$');
        // A grant written around `clients:grant`, which refuses it.
        $this->clientGrants->save(ClientGrant::grant(
            $outsider->id,
            $system,
            ScopeSet::fromString('read:users'),
            $this->clock->now(),
        ));
        $this->clientGrants->save(ClientGrant::grant(
            $this->client->id,
            $system,
            ScopeSet::fromString('read:users'),
            $this->clock->now(),
        ));
        $parameters = RequestParameters::fromMap([
            'grant_type' => 'client_credentials',
            'audience' => 'https://management.example/api/v1/',
        ]);

        self::assertSame('read:users', $this->grant->issue($parameters, $this->client)->scope->toString());
        $this->expectExceptionObject(OAuth2Error::accessDenied('Third-party applications cannot access this API.'));
        $this->grant->issue($parameters, $outsider);
    }

    /**
     * @param list<string> $permissions
     */
    private function api(string $identifier, array $permissions): ResourceServer
    {
        $api = ResourceServer::register(
            ResourceServerId::fromString('rs_' . substr(hash('sha256', $identifier), 0, 16)),
            Audience::fromString($identifier),
            'An API',
            array_map(static fn (string $value): Permission => Permission::of($value), $permissions),
            $this->clock->now(),
        );
        $this->resourceServers->save($api);

        return $api;
    }
}
