<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Management;

use Clavia\Application\Management\Caller\ManagementCaller;
use Clavia\Application\Management\Clients\ClientChanges;
use Clavia\Application\Management\Clients\ClientConnections;
use Clavia\Application\Management\Clients\ClientWithSecret;
use Clavia\Application\Management\Clients\DeleteClient;
use Clavia\Application\Management\Clients\NewClient;
use Clavia\Application\Management\Clients\ReadClients;
use Clavia\Application\Management\Clients\RegisterClient;
use Clavia\Application\Management\Clients\RotateClientSecret;
use Clavia\Application\Management\Clients\UpdateClient;
use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryConnectionRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Registering, changing, rotating and deleting clients through the Management API's use cases.
 */
final class ClientsTest extends TestCase
{
    private InMemoryClientRepository $clients;
    private FakePasswordHasher $hasher;
    private SecretGenerator $secrets;
    private InMemoryConnectionRepository $connections;

    #[\Override]
    protected function setUp(): void
    {
        $this->clients = new InMemoryClientRepository();
        $this->hasher = new FakePasswordHasher();
        $this->secrets = new SecretGenerator(new SeededRandomSource(1));
        $this->connections = new InMemoryConnectionRepository($this->clients);
    }

    public function testAConfidentialClientGetsASecretShownOnceAndStoredHashed(): void
    {
        $registered = $this->register(new NewClient('Billing', 'confidential', grantTypes: ['client_credentials']));

        self::assertNotNull($registered->secret);
        self::assertSame(ClientAuthMethod::ClientSecretBasic, $registered->client->authMethod);
        $stored = $this->clients->find($registered->client->id);
        self::assertNotNull($stored);
        self::assertNotSame($registered->secret, $stored->secretHash());
        self::assertTrue($this->hasher->verify($registered->secret, (string) $stored->secretHash()));
    }

    public function testOwnershipIsWrittenIntoTheGeneratedId(): void
    {
        $ours = $this->register(new NewClient('Ours', 'confidential', grantTypes: ['client_credentials']));
        $theirs = $this->register(new NewClient(
            'Theirs',
            'confidential',
            grantTypes: ['client_credentials'],
            firstParty: false,
        ));

        self::assertTrue($ours->client->isFirstParty());
        self::assertMatchesRegularExpression('/^[A-Za-z0-9]{32}$/D', $ours->client->id->value);
        self::assertFalse($theirs->client->isFirstParty());
        self::assertMatchesRegularExpression('/^tpc_[A-Za-z0-9]{32}$/D', $theirs->client->id->value);
    }

    public function testAPublicClientGetsNoSecretAndAuthenticatesWithNone(): void
    {
        $registered = $this->register(new NewClient(
            redirectUris: ['https://spa.test/callback'],
            grantTypes: ['authorization_code'],
            responseTypes: ['code'],
        ));

        self::assertNull($registered->secret);
        self::assertSame(ClientType::Public, $registered->client->type);
        self::assertSame(ClientAuthMethod::None, $registered->client->authMethod);
    }

    #[DataProvider('incoherent')]
    public function testARegistrationNoFlowCouldServeIsRefused(NewClient $new): void
    {
        $this->expectException(InvalidValue::class);

        $this->register($new);
    }

    /** @return iterable<string, array{NewClient}> */
    public static function incoherent(): iterable
    {
        yield 'an unknown type' => [new NewClient(type: 'trusted')];
        yield 'an unknown grant' => [new NewClient(grantTypes: ['password'])];
        yield 'a confidential client without a secret method' => [
            new NewClient(type: 'confidential', authMethod: 'none'),
        ];
        yield 'a public client with one' => [new NewClient(authMethod: 'client_secret_post')];
        yield 'client credentials for a public client' => [new NewClient(grantTypes: ['client_credentials'])];
        yield 'the code flow without a redirect URI' => [
            new NewClient(grantTypes: ['authorization_code'], responseTypes: ['code']),
        ];
        yield 'half of the code flow' => [
            new NewClient(redirectUris: ['https://spa.test/cb'], grantTypes: ['authorization_code']),
        ];
        yield 'a relative redirect URI' => [
            new NewClient(redirectUris: ['/cb'], grantTypes: ['authorization_code'], responseTypes: ['code']),
        ];
    }

    public function testAnUpdateIsCheckedAsTheWholeNewRegistration(): void
    {
        $client = $this->register(new NewClient(
            redirectUris: ['https://spa.test/callback'],
            grantTypes: ['authorization_code'],
            responseTypes: ['code'],
        ))->client;
        $update = new UpdateClient($this->clients);

        self::assertSame('Renamed', $update($client->id, new ClientChanges(name: 'Renamed'))->name);

        $this->expectException(InvalidValue::class);
        $update($client->id, new ClientChanges(redirectUris: []));
    }

    public function testRotatingReplacesTheSecret(): void
    {
        $registered = $this->register(new NewClient(type: 'confidential', grantTypes: ['client_credentials']));

        $rotated = new RotateClientSecret($this->clients, $this->hasher, $this->secrets)($registered->client->id);

        self::assertNotNull($rotated->secret);
        self::assertNotSame($registered->secret, $rotated->secret);
        $stored = (string) $this->clients->find($registered->client->id)?->secretHash();
        self::assertTrue($this->hasher->verify($rotated->secret, $stored));
        self::assertFalse($this->hasher->verify((string) $registered->secret, $stored));
    }

    public function testAPublicClientHasNoSecretToRotate(): void
    {
        $client = $this->register(new NewClient())->client;

        $this->expectException(InvalidValue::class);

        new RotateClientSecret($this->clients, $this->hasher, $this->secrets)($client->id);
    }

    public function testDeletingRemovesTheClientButNotTheCallersOwn(): void
    {
        $client = $this->register(new NewClient(type: 'confidential', grantTypes: ['client_credentials']))->client;
        $delete = new DeleteClient($this->clients);

        try {
            $delete($client->id, new ManagementCaller($client->id, null, ScopeSet::empty()));
            self::fail('The caller deleted its own client.');
        } catch (Conflict) {
            self::assertNotNull($this->clients->find($client->id));
        }

        $delete($client->id, new ManagementCaller(ClientId::fromString('other'), null, ScopeSet::empty()));
        self::assertNull($this->clients->find($client->id));
    }

    public function testAnUnknownClientIsNotFound(): void
    {
        $this->expectException(NotFound::class);

        new ReadClients($this->clients)->one(ClientId::fromString('nobody'));
    }

    public function testTheGrantTypesAreKeptAsRegistered(): void
    {
        $client = $this->register(new NewClient(type: 'confidential', grantTypes: ['client_credentials']))->client;

        self::assertSame([GrantType::ClientCredentials], $client->grantTypes);
    }

    public function testAFirstPartyClientNamingNoConnectionsGetsEveryOne(): void
    {
        $client = $this->register(new NewClient('SPA', redirectUris: ['https://app.example/cb']))->client;

        self::assertSame(['email', 'github', 'google', 'password'], self::names($client->connections));
    }

    public function testTheConnectionsNamedAreTheOnesEnabled(): void
    {
        $client = $this->register(new NewClient(
            'SPA',
            redirectUris: ['https://app.example/cb'],
            connections: ['password', 'google', 'password'],
        ))->client;

        self::assertSame(['google', 'password'], self::names($client->connections));
    }

    public function testAnUnknownConnectionIsNotFound(): void
    {
        $this->expectException(NotFound::class);

        $this->register(new NewClient('SPA', redirectUris: ['https://app.example/cb'], connections: ['gitlab']));
    }

    public function testAThirdPartyClientGetsNoListAndCannotNameOne(): void
    {
        $theirs = $this->register(new NewClient(
            'Theirs',
            'confidential',
            grantTypes: ['client_credentials'],
            firstParty: false,
        ))->client;
        self::assertSame([], $theirs->connections);

        $this->expectException(InvalidValue::class);

        $this->register(new NewClient(
            'Theirs',
            'confidential',
            grantTypes: ['client_credentials'],
            firstParty: false,
            connections: ['password'],
        ));
    }

    public function testTheConnectionsOfAClientAreReplacedWhole(): void
    {
        $client = $this->register(new NewClient('SPA', redirectUris: ['https://app.example/cb']))->client;
        $replace = new ClientConnections($this->clients, $this->connections);

        $updated = $replace($client->id, ['github']);

        self::assertSame(['github'], self::names($updated->connections));
        self::assertSame(['github'], self::names($this->clients->find($client->id)?->connections ?? []));
        self::assertSame([], self::names($replace($client->id, [])->connections));
    }

    public function testReplacingTheConnectionsOfAnUnknownClientIsNotFound(): void
    {
        $this->expectException(NotFound::class);

        new ClientConnections($this->clients, $this->connections)(ClientId::fromString('nobody'), []);
    }

    /**
     * @param list<ConnectionName> $connections
     *
     * @return list<string>
     */
    private static function names(array $connections): array
    {
        return array_map(static fn (ConnectionName $name): string => $name->value, $connections);
    }

    private function register(NewClient $new): ClientWithSecret
    {
        return new RegisterClient(
            $this->clients,
            $this->hasher,
            $this->secrets,
            new FrozenClock(),
            new ClientConnections($this->clients, $this->connections),
        )($new);
    }
}
