<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration;

use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;
use ClaviaTest\Support\TestStorage;
use LogicException;

/**
 * The harness itself: every other storage test depends on it starting clean, and on it
 * refusing to wipe anything that is not test storage.
 */
final class TestStorageTest extends IntegrationTestCase
{
    private const array VARIABLES = ['CLAVIA_TEST_DATABASE_URL', 'CLAVIA_TEST_REDIS_URL'];

    /**
     * The variables as the run started with them. They are put back after each test, not
     * removed: under docker-compose they name `db-test` and `redis`, and every later test
     * that builds the application reads them again.
     *
     * @var array<string, string|false>
     */
    private array $environment = [];

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        foreach (self::VARIABLES as $name) {
            $this->environment[$name] = getenv($name);
        }
    }

    #[\Override]
    protected function tearDown(): void
    {
        TestStorage::database()->executeScript('DROP TABLE IF EXISTS storage_probe');
        foreach ($this->environment as $name => $value) {
            putenv($value === false ? $name : $name . '=' . $value);
        }

        parent::tearDown();
    }

    public function testResetEmptiesEveryTableAndRedisButKeepsTheSchema(): void
    {
        $db = TestStorage::database();
        $db->executeScript('CREATE TABLE storage_probe (id integer GENERATED ALWAYS AS IDENTITY, v text)');
        $db->execute("INSERT INTO storage_probe (v) VALUES ('a'), ('b')");
        TestStorage::redis()->set('leftover', '1');

        TestStorage::reset();

        self::assertSame(0, $db->fetchValue('SELECT count(*) FROM storage_probe'));
        self::assertSame(0, TestStorage::redis()->dbSize());
        // Identity sequences restart, so generated ids are the same from one test to the next.
        self::assertSame(1, $db->fetchValue("INSERT INTO storage_probe (v) VALUES ('c') RETURNING id"));
        self::assertNotNull($db->fetchValue("SELECT to_regclass('schema_migrations')"));
    }

    public function testItRefusesADatabaseThatIsNotATestDatabase(): void
    {
        putenv('CLAVIA_TEST_DATABASE_URL=postgresql://clavia:clavia@localhost:5433/clavia');

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('must end in "_test"');

        TestEnvironment::databaseUrl();
    }

    public function testItRefusesRedisDatabaseZero(): void
    {
        foreach (['redis://localhost:6379/0', 'redis://localhost:6379'] as $url) {
            putenv('CLAVIA_TEST_REDIS_URL=' . $url);

            try {
                TestEnvironment::redisUrl();
                self::fail(sprintf('%s was accepted.', $url));
            } catch (LogicException $refusal) {
                self::assertStringContainsString('Redis database 0', $refusal->getMessage());
            }
        }
    }
}
