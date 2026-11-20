<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use LogicException;

/**
 * The configuration every test that boots the application or touches storage runs with.
 *
 * Never the machine's `.env`: the suite must not inherit a developer's database, Redis,
 * KMS key or domain. Storage is the throwaway `db-test` PostgreSQL and database 1 of
 * Redis — both are wiped between tests, and doing that to a development database or to
 * Redis database 0 would destroy someone's data and sign them out mid-session.
 *
 * Where those services are is the only thing the environment may change:
 * `CLAVIA_TEST_DATABASE_URL` and `CLAVIA_TEST_REDIS_URL` (set by docker-compose.yml for
 * the `php` container and by the CI workflow).
 */
final class TestEnvironment
{
    /**
     * A reserved TLD (RFC 2606), so the suite never depends on a real domain — and never
     * issues a redirect anywhere real.
     */
    public const string ROOT_DOMAIN = 'clavia.test';

    /**
     * base64 of the bytes 0x00…0x1f. Constant on purpose: nothing the suite encrypts is
     * a secret worth generating, and a developer's real key must not be used.
     */
    public const string SECRET_ENCRYPTION_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';

    private const string DEFAULT_DATABASE_URL = 'postgresql://clavia:clavia@localhost:5434/clavia_test';

    private const string DEFAULT_REDIS_URL = 'redis://localhost:6379/1';

    private function __construct()
    {
    }

    /**
     * The `CLAVIA_*` variables the application is built from under test.
     *
     * @return array<string, string>
     */
    public static function variables(): array
    {
        return [
            'CLAVIA_ENV' => 'development',
            'CLAVIA_ROOT_DOMAIN' => self::ROOT_DOMAIN,
            'CLAVIA_DATABASE_URL' => self::databaseUrl(),
            'CLAVIA_REDIS_URL' => self::redisUrl(),
            'CLAVIA_SECRET_ENCRYPTION_KEY' => self::SECRET_ENCRYPTION_KEY,
            // The suite exercises the postgres backend; a developer's KMS configuration
            // must not leak in and start signing test tokens against a real provider.
            'CLAVIA_SIGNING_BACKEND' => 'postgres',
        ];
    }

    /**
     * @throws LogicException When the URL does not name a database that is safe to wipe.
     */
    public static function databaseUrl(): string
    {
        $url = self::fromEnvironment('CLAVIA_TEST_DATABASE_URL') ?? self::DEFAULT_DATABASE_URL;

        $database = (string) parse_url($url, PHP_URL_PATH);
        if (! str_ends_with($database, '_test')) {
            throw new LogicException(sprintf(
                'Refusing to run tests against the database "%s": the suite truncates every table, so the '
                . 'database name must end in "_test".',
                ltrim($database, '/'),
            ));
        }

        return $url;
    }

    /**
     * @throws LogicException When the URL names Redis database 0.
     */
    public static function redisUrl(): string
    {
        $url = self::fromEnvironment('CLAVIA_TEST_REDIS_URL') ?? self::DEFAULT_REDIS_URL;

        $database = ltrim((string) parse_url($url, PHP_URL_PATH), '/');
        if ($database === '' || $database === '0') {
            throw new LogicException(
                'Refusing to run tests against Redis database 0: the suite flushes its database between '
                . 'tests. Use another one, e.g. redis://localhost:6379/1.',
            );
        }

        return $url;
    }

    private static function fromEnvironment(string $name): ?string
    {
        $value = getenv($name);

        return $value === false || $value === '' ? null : $value;
    }
}
