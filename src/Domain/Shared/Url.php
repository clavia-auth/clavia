<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Shared;

use Uri\Rfc3986\Uri;

/**
 * An absolute URL the server was given: a redirect URI, an issuer, a logout endpoint.
 *
 * The string is kept exactly as received. Comparison is byte for byte
 * ({@see self::equals()}): OAuth 2.1 requires redirect URIs to match exactly, and
 * every "equivalent" form a normaliser would accept — a different case, an explicit
 * default port, a dot segment — is a place where a validator and a browser can
 * disagree about where a response goes. The parsed view exists only to answer
 * questions *about* the URL (its scheme, its origin), never to rewrite it.
 */
final readonly class Url
{
    private const array DEFAULT_PORTS = ['http' => 80, 'https' => 443];

    private const array LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

    /**
     * @param non-empty-string $value
     */
    private function __construct(
        public string $value,
        private Uri $uri,
    ) {
    }

    /**
     * @throws InvalidValue When the value is not an absolute URL with a scheme and a host, carries
     *                      credentials, or holds whitespace or a control character.
     */
    public static function fromString(string $value): self
    {
        if ($value === '' || preg_match('/[\x00-\x20\x7F]/', $value) === 1) {
            throw new InvalidValue('A URL must not be empty or contain whitespace or control characters.');
        }

        $uri = Uri::parse($value);
        if ($uri === null || $uri->getScheme() === null || ($uri->getHost() ?? '') === '') {
            throw new InvalidValue('A URL must be absolute, with a scheme and a host.');
        }

        // user:password@host is how a URL is made to look like it points somewhere it does not.
        if ($uri->getUserInfo() !== null) {
            throw new InvalidValue('A URL must not carry credentials.');
        }

        return new self($value, $uri);
    }

    /** Lower-case scheme: `https`. */
    public function scheme(): string
    {
        return (string) $this->uri->getScheme();
    }

    /** Lower-case host; an IPv6 literal keeps its brackets: `[::1]`. */
    public function host(): string
    {
        return (string) $this->uri->getHost();
    }

    /** The explicit port, or the scheme's default when the URL names none; null for an unknown scheme. */
    public function port(): ?int
    {
        return $this->uri->getPort() ?? (self::DEFAULT_PORTS[$this->scheme()] ?? null);
    }

    public function path(): string
    {
        return $this->uri->getPath();
    }

    public function hasQuery(): bool
    {
        return $this->uri->getQuery() !== null;
    }

    public function hasFragment(): bool
    {
        return $this->uri->getFragment() !== null;
    }

    public function isHttps(): bool
    {
        return $this->scheme() === 'https';
    }

    /** `localhost`, `127.0.0.1` or `[::1]` — the hosts a native app or a development box redirects to. */
    public function isLoopback(): bool
    {
        return in_array($this->host(), self::LOOPBACK_HOSTS, true);
    }

    /**
     * The origin (RFC 6454): scheme, host and port, with a default port left out.
     * This is the form a Content-Security-Policy source and an `Origin` header use.
     */
    public function origin(): string
    {
        $origin = $this->scheme() . '://' . $this->host();
        $port = $this->uri->getPort();

        if ($port === null || $port === (self::DEFAULT_PORTS[$this->scheme()] ?? null)) {
            return $origin;
        }

        return $origin . ':' . $port;
    }

    /** Exact, byte-for-byte equality — the only comparison a redirect URI is ever given. */
    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }

    public function toString(): string
    {
        return $this->value;
    }
}
