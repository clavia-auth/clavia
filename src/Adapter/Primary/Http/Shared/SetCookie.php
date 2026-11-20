<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use InvalidArgumentException;

/**
 * One `Set-Cookie` header value (RFC 6265 §4.1).
 *
 * Every cookie this server sets is `HttpOnly` and `SameSite=Lax`, and none carries a
 * `Domain` attribute: a host-only cookie is never shared with another subdomain of the
 * deployment. Only the name, value, lifetime, path and `Secure` vary.
 */
final readonly class SetCookie
{
    /** The past instant that tells browsers too old to read `Max-Age=0` to drop a cookie. */
    private const string EPOCH = 'Thu, 01 Jan 1970 00:00:00 GMT';

    /**
     * @param non-empty-string $name
     * @param non-negative-int $maxAge Seconds; zero deletes the cookie.
     */
    private function __construct(
        public string $name,
        private string $value,
        private int $maxAge,
        private string $path,
        private bool $secure,
    ) {
        // Only token characters in a name, and only cookie-octets in a value: nothing
        // that could end the attribute list early or split the header.
        if (preg_match('/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$/D', $name) !== 1) {
            throw new InvalidArgumentException('A cookie name is an RFC 9110 token.');
        }

        if (preg_match('/^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/D', $value) !== 1) {
            throw new InvalidArgumentException('A cookie value holds no space, quote, comma, semicolon or backslash.');
        }
    }

    /**
     * @param non-empty-string $name
     * @param positive-int     $maxAge
     */
    public static function create(string $name, string $value, int $maxAge, string $path, bool $secure): self
    {
        return new self($name, $value, $maxAge, $path, $secure);
    }

    /**
     * Ask the browser to drop a cookie. Browsers key cookies by name, domain and path, so
     * the path must be the one it was set with, or the deletion does nothing.
     *
     * @param non-empty-string $name
     */
    public static function expire(string $name, string $path, bool $secure): self
    {
        return new self($name, '', 0, $path, $secure);
    }

    public function toString(): string
    {
        $attributes = [$this->name . '=' . $this->value, 'Max-Age=' . $this->maxAge];
        if ($this->maxAge === 0) {
            $attributes[] = 'Expires=' . self::EPOCH;
        }

        $attributes[] = 'Path=' . $this->path;
        if ($this->secure) {
            $attributes[] = 'Secure';
        }

        $attributes[] = 'HttpOnly';
        $attributes[] = 'SameSite=Lax';

        return implode('; ', $attributes);
    }
}
