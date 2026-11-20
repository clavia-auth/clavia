<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use InvalidArgumentException;
use Uri\Rfc3986\Uri;

/**
 * `CLAVIA_DATABASE_URL`, taken apart into what PDO wants.
 *
 * `postgresql://user:password@host:5432/database?sslmode=require`. The credentials are
 * kept out of the DSN and handed to PDO separately, so a password holding `;` or `=`
 * cannot be read as a DSN option.
 */
final readonly class PostgresUrl
{
    private const array SCHEMES = ['postgresql', 'postgres'];

    /** libpq keywords a URL may set through its query string. */
    private const array DSN_OPTIONS = [
        'sslmode', 'sslrootcert', 'sslcert', 'sslkey', 'connect_timeout', 'application_name', 'options',
    ];

    private function __construct(
        public string $dsn,
        public ?string $username,
        #[\SensitiveParameter] public ?string $password,
    ) {
    }

    /**
     * @throws InvalidArgumentException When the URL is not a PostgreSQL URL naming a host and a database.
     */
    public static function parse(#[\SensitiveParameter] string $url): self
    {
        $uri = Uri::parse($url);
        if ($uri === null || ! in_array($uri->getScheme(), self::SCHEMES, true)) {
            throw new InvalidArgumentException('The database URL must start with postgresql:// (or postgres://).');
        }

        $host = $uri->getHost() ?? '';
        $database = rawurldecode(ltrim($uri->getPath(), '/'));
        if ($host === '' || $database === '') {
            throw new InvalidArgumentException('The database URL must name a host and a database.');
        }

        $parts = [
            'host=' . self::quote(trim($host, '[]')),
            'port=' . ($uri->getPort() ?? 5432),
            'dbname=' . self::quote($database),
        ];

        parse_str($uri->getQuery() ?? '', $query);
        foreach ($query as $name => $value) {
            if (! in_array($name, self::DSN_OPTIONS, true) || ! is_string($value)) {
                throw new InvalidArgumentException(sprintf(
                    'The database URL has an unsupported option "%s"; supported: %s.',
                    (string) $name,
                    implode(', ', self::DSN_OPTIONS),
                ));
            }
            $parts[] = $name . '=' . self::quote($value);
        }

        $username = $uri->getUsername();
        $password = $uri->getPassword();

        return new self(
            'pgsql:' . implode(';', $parts),
            $username === null || $username === '' ? null : rawurldecode($username),
            $password === null || $password === '' ? null : rawurldecode($password),
        );
    }

    /** Quote a value for a libpq connection string: single quotes, backslash-escaped. */
    private static function quote(string $value): string
    {
        return "'" . addcslashes($value, "'\\") . "'";
    }
}
