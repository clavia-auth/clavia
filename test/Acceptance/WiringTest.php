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
use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\SchemaMigrator;
use Clavia\Application\Port\SecretCipher;
use Clavia\Application\Port\TransactionManager;
use Clavia\Bootstrap\ConfigProvider;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use ClaviaTest\Support\AcceptanceTestCase;
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

    public function testHealthzNeedsNeitherPostgresNorRedis(): void
    {
        $this->boot([
            'CLAVIA_DATABASE_URL' => 'postgresql://nobody@127.0.0.1:1/nothing_test?connect_timeout=1',
            'CLAVIA_REDIS_URL' => 'redis://127.0.0.1:1/1',
        ]);

        self::assertSame(200, $this->get('/healthz')->getStatusCode());
    }
}
