<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Infrastructure\Persistence;

use Clavia\Infrastructure\Persistence\PhpDb\PostgresUrl;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PostgresUrlTest extends TestCase
{
    public function testItSeparatesTheCredentialsFromTheDsn(): void
    {
        $url = PostgresUrl::parse('postgresql://clavia:s3cret@db.internal:5433/clavia');

        self::assertSame("pgsql:host='db.internal';port=5433;dbname='clavia'", $url->dsn);
        self::assertSame('clavia', $url->username);
        self::assertSame('s3cret', $url->password);
    }

    public function testAPasswordFullOfDsnSyntaxNeverReachesTheDsn(): void
    {
        $url = PostgresUrl::parse('postgresql://app:p%40ss%3Bhost%3Devil%27@db:5432/clavia');

        self::assertSame("p@ss;host=evil'", $url->password);
        self::assertStringNotContainsString('evil', $url->dsn);
    }

    public function testThePortDefaultsAndTheShortSchemeIsAccepted(): void
    {
        $url = PostgresUrl::parse('postgres://app@db/clavia');

        self::assertSame("pgsql:host='db';port=5432;dbname='clavia'", $url->dsn);
        self::assertSame('app', $url->username);
        self::assertNull($url->password);
    }

    public function testConnectionOptionsComeFromTheQueryString(): void
    {
        $url = PostgresUrl::parse('postgresql://app@db/clavia?sslmode=verify-full&connect_timeout=3');

        self::assertSame(
            "pgsql:host='db';port=5432;dbname='clavia';sslmode='verify-full';connect_timeout='3'",
            $url->dsn,
        );
    }

    public function testValuesAreQuotedSoTheyCannotAddOptions(): void
    {
        $url = PostgresUrl::parse("postgresql://app@db/cla%27via%3Bhost%3Devil?application_name=a%27%20b");

        self::assertSame(
            "pgsql:host='db';port=5432;dbname='cla\\'via;host=evil';application_name='a\\' b'",
            $url->dsn,
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function refusedUrls(): iterable
    {
        yield 'another database' => ['mysql://app@db/clavia', 'must start with postgresql://'];
        yield 'the SQLAlchemy driver suffix' => ['postgresql+psycopg://app@db/clavia', 'must start with postgresql://'];
        yield 'not a URL' => ['clavia', 'must start with postgresql://'];
        yield 'no database' => ['postgresql://app@db', 'must name a host and a database'];
        yield 'no host' => ['postgresql:///clavia', 'must name a host and a database'];
        yield 'an unknown option' => ['postgresql://app@db/clavia?sslmod=require', 'unsupported option "sslmod"'];
    }

    #[DataProvider('refusedUrls')]
    public function testItRefusesWhatItCannotConnectWith(string $url, string $reason): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($reason);

        PostgresUrl::parse($url);
    }
}
