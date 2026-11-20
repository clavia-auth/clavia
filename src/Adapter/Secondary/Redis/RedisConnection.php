<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use InvalidArgumentException;
use Redis;
use Uri\Rfc3986\Uri;

/**
 * The shared Redis connection, opened on first use.
 *
 * Redis holds only the short-TTL material described under "Storage split" in
 * CLAUDE.md: browser sessions, the pending login state, failed-login counters, MFA and
 * passwordless challenges, social-login state, device codes. Everything stored here
 * expires on its own, nothing downstream audits it, and losing the store signs everyone
 * out rather than corrupting anything. Anything that must survive a restart or be
 * consumed exactly once lives in PostgreSQL instead.
 *
 * Built from `CLAVIA_REDIS_URL`: `redis://[user:password@]host[:port][/database]`, or
 * `rediss://` for TLS.
 */
final class RedisConnection
{
    private const float CONNECT_TIMEOUT_SECONDS = 2.0;

    private const float READ_TIMEOUT_SECONDS = 2.0;

    private ?Redis $client = null;

    public function __construct(#[\SensitiveParameter] private readonly string $url)
    {
    }

    /**
     * The connected client. Every store adapter reaches Redis through this.
     *
     * @throws InvalidArgumentException When the URL is not a Redis URL.
     * @throws \RedisException          When the server cannot be reached or refuses the credentials.
     */
    public function client(): Redis
    {
        if ($this->client !== null) {
            return $this->client;
        }

        $uri = Uri::parse($this->url);
        $scheme = $uri?->getScheme();
        $host = $uri?->getHost() ?? '';
        if ($uri === null || ! in_array($scheme, ['redis', 'rediss'], true) || $host === '') {
            throw new InvalidArgumentException(
                'The Redis URL must look like redis://host:6379/0 (or rediss:// for TLS).',
            );
        }

        $database = ltrim($uri->getPath(), '/');
        if ($database !== '' && ! ctype_digit($database)) {
            throw new InvalidArgumentException('The Redis URL path must be a database number, e.g. /0.');
        }

        $client = new Redis();
        $client->connect(
            ($scheme === 'rediss' ? 'tls://' : '') . trim($host, '[]'),
            $uri->getPort() ?? 6379,
            self::CONNECT_TIMEOUT_SECONDS,
            null,
            0,
            self::READ_TIMEOUT_SECONDS,
        );

        $username = rawurldecode($uri->getUsername() ?? '');
        $password = $uri->getPassword();
        if ($password !== null && $password !== '') {
            $client->auth($username === '' ? rawurldecode($password) : [$username, rawurldecode($password)]);
        }

        if ($database !== '' && $database !== '0') {
            $client->select((int) $database);
        }

        return $this->client = $client;
    }
}
