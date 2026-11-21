<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Application\Port\IdentityProviders;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\SchemaMigrator;
use Clavia\Application\Port\SecretCipher;
use Clavia\Application\Port\TokenSigner;
use Clavia\Application\Port\TransactionManager;
use Clavia\Bootstrap\ConfigProvider;
use Clavia\Bootstrap\Container\HttpClientFactory;
use Clavia\Configuration\InvalidSettings;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionStrategy;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use ClaviaTest\Support\AcceptanceTestCase;
use DateTimeImmutable;
use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use Laminas\ServiceManager\Exception\ServiceNotCreatedException;
use Psr\Http\Client\ClientInterface;
use Symfony\Component\Console\Application as ConsoleApplication;

/**
 * The composition root, exercised: every service it declares can be built, and the
 * ports resolve to adapters that work against the real storage.
 */
final class WiringTest extends AcceptanceTestCase
{
    public function testEveryDeclaredServiceCanBeBuilt(): void
    {
        $dependencies = new ConfigProvider()()['dependencies'];
        $services = array_keys($dependencies['factories'] + $dependencies['invokables']);

        foreach ($services as $service) {
            self::assertIsObject($this->container()->get($service), $service);
        }
    }

    public function testEveryConsoleCommandIsRegisteredUnderItsOwnName(): void
    {
        /** @var ConsoleApplication $console */
        $console = $this->container()->get(ConsoleApplication::class);

        foreach (ConfigProvider::CONSOLE_COMMANDS as $name => $service) {
            self::assertTrue($console->has($name), $name);
            self::assertInstanceOf($service, $console->get($name));
            self::assertSame($name, $console->get($name)->getName());
        }
    }

    public function testASigningBackendThatDoesNotExistYetIsRefusedByName(): void
    {
        // An operator who configured a KMS must never end up signing from PostgreSQL unawares.
        $this->boot([
            'CLAVIA_SIGNING_BACKEND' => 'aws-kms',
            'CLAVIA_SIGNING_KEY_REF' => 'arn:aws:kms:eu-west-1:1:key/x',
        ]);

        try {
            $this->container()->get(TokenSigner::class);
            self::fail('A signer was built for a backend that does not exist.');
        } catch (ServiceNotCreatedException $refusal) {
            self::assertInstanceOf(InvalidSettings::class, $refusal->getPrevious());
            self::assertStringContainsString("CLAVIA_SIGNING_BACKEND='aws-kms'", $refusal->getPrevious()->getMessage());
        }
    }

    public function testASigningAlgorithmNoKeyCanProduceIsRefused(): void
    {
        $this->boot(['CLAVIA_SIGNING_ALGORITHM' => 'HS256']);

        $this->expectException(ServiceNotCreatedException::class);

        $this->container()->get(SigningAlgorithm::class);
    }

    public function testTheDatabaseOfTheContainerIsTheTestDatabase(): void
    {
        /** @var Database $database */
        $database = $this->container()->get(Database::class);

        self::assertSame('clavia_test', $database->fetchValue('SELECT current_database()'));
    }

    public function testATransactionOpenedThroughThePortIsARealOne(): void
    {
        /** @var TransactionManager $transactions */
        $transactions = $this->container()->get(TransactionManager::class);
        /** @var Database $database */
        $database = $this->container()->get(Database::class);

        $inside = $transactions->transactional(static fn (): bool => $database->inTransaction());

        self::assertTrue($inside);
        self::assertFalse($database->inTransaction());
    }

    public function testThePortsResolveToWorkingAdapters(): void
    {
        $container = $this->container();
        /** @var PasswordHasher $hasher */
        $hasher = $container->get(PasswordHasher::class);
        /** @var SecretCipher $cipher */
        $cipher = $container->get(SecretCipher::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var SchemaMigrator $migrator */
        $migrator = $container->get(SchemaMigrator::class);

        self::assertTrue($hasher->verify('pw', $hasher->hash('pw')));
        self::assertSame('seed', $cipher->decrypt($cipher->encrypt('seed', 'ctx'), 'ctx'));
        self::assertSame('UTC', $clock->now()->getTimezone()->getName());
        self::assertSame(16, strlen($random->bytes(16)));
        // The suite migrated the test database from migrations/: nothing is left pending.
        self::assertSame([], $migrator->migrate());
    }

    public function testOutboundHttpIsABoundedGuzzleClientThatFollowsNoRedirect(): void
    {
        $client = $this->container()->get(ClientInterface::class);

        self::assertInstanceOf(Client::class, $client);
        self::assertSame(HttpClientFactory::TIMEOUT, $client->getConfig(RequestOptions::TIMEOUT));
        self::assertSame(HttpClientFactory::CONNECT_TIMEOUT, $client->getConfig(RequestOptions::CONNECT_TIMEOUT));
        self::assertFalse($client->getConfig(RequestOptions::ALLOW_REDIRECTS));
    }

    public function testAProviderIsOfferedOnlyWithBothHalvesOfItsCredentials(): void
    {
        $this->boot([
            'CLAVIA_GOOGLE_CLIENT_ID' => 'id',
            'CLAVIA_GOOGLE_CLIENT_SECRET' => 'secret',
            'CLAVIA_GITHUB_CLIENT_ID' => 'id',
        ]);

        /** @var IdentityProviders $providers */
        $providers = $this->container()->get(IdentityProviders::class);

        self::assertSame('google', $providers->for(self::social('google'))?->name()->value);
        self::assertNull($providers->for(self::social('github')));
    }

    public function testHealthzNeedsNeitherPostgresNorRedis(): void
    {
        $this->boot([
            'CLAVIA_DATABASE_URL' => 'postgresql://nobody@127.0.0.1:1/nothing_test?connect_timeout=1',
            'CLAVIA_REDIS_URL' => 'redis://127.0.0.1:1/1',
        ]);

        self::assertSame(200, $this->get('/healthz')->getStatusCode());
    }

    private static function social(string $name): Connection
    {
        return Connection::reconstitute(
            ConnectionName::fromString($name),
            ucfirst($name),
            ConnectionStrategy::Social,
            true,
            false,
            null,
            new DateTimeImmutable('2026-01-01T00:00:00Z'),
        );
    }
}
