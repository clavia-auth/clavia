<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Adapter\Secondary\Persistence\Migrations\SqlFileMigrator;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PostgresUrl;
use Clavia\Adapter\Secondary\Redis\RedisConnection;
use Clavia\Adapter\Secondary\System\SystemClock;
use Redis;

/**
 * The suite's PostgreSQL and Redis: migrated once per run, wiped between tests.
 *
 * The schema is built by the real migrations in `migrations/`, not by a shortcut, so
 * the suite also proves that the migrations produce the schema the code expects.
 */
final class TestStorage
{
    private static ?Database $database = null;

    private static ?Redis $redis = null;

    private static bool $migrated = false;

    private function __construct()
    {
    }

    /** One connection for the whole run, on the test database's `public` schema. */
    public static function database(): Database
    {
        return self::$database ??= new Database(PostgresUrl::parse(TestEnvironment::databaseUrl()));
    }

    public static function redis(): Redis
    {
        return self::$redis ??= new RedisConnection(TestEnvironment::redisUrl())->client();
    }

    /** Bring the test database to the current schema. Done once; later calls cost nothing. */
    public static function migrate(): void
    {
        if (self::$migrated) {
            return;
        }

        new SqlFileMigrator(self::database(), __DIR__ . '/../../migrations', new SystemClock())->migrate();
        self::$migrated = true;
    }

    /**
     * Empty every table and the Redis database, so each test starts from a known state.
     * The migration history is kept: the schema stays, only its contents go.
     */
    public static function reset(): void
    {
        self::migrate();

        /** @var list<array{tablename: string}> $tables */
        $tables = self::database()->fetchAll(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> :history",
            ['history' => SqlFileMigrator::TABLE],
        );

        if ($tables !== []) {
            $names = array_map(
                static fn (array $table): string => '"' . str_replace('"', '""', $table['tablename']) . '"',
                $tables,
            );
            self::database()->executeScript('TRUNCATE ' . implode(', ', $names) . ' RESTART IDENTITY CASCADE');
        }

        self::seedBuiltInConnections();

        self::redis()->flushDB();
    }

    /**
     * Put back the connections `0019_connections.sql` seeds, which the truncation took:
     * every account belongs to one, and a deployment always has them. Kept in step with
     * that migration by hand.
     */
    private static function seedBuiltInConnections(): void
    {
        self::database()->executeScript(
            'INSERT INTO connections (name, display_name, strategy, is_enabled, is_domain_connection, created_at)'
            . " VALUES ('password', 'Username-Password', 'database', true, true, now()),"
            . " ('google', 'Google', 'social', true, false, now()),"
            . " ('github', 'GitHub', 'social', true, false, now())",
        );
    }
}
