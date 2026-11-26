<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi;

/**
 * A media type as a `Content-Type` header gives it (RFC 9110 §8.3.1), or a media range
 * as a Content map key gives it (`application/json`, `application/*`, `*\/*`).
 * Type and subtype are case-insensitive and kept lower-cased; parameters other than
 * `charset` are ignored.
 */
final readonly class MediaType
{
    private function __construct(
        public string $type,
        public string $subtype,
        public ?string $charset,
    ) {
    }

    /** Null when `$value` is not `type/subtype` with optional parameters. */
    public static function parse(string $value): ?self
    {
        $parts = explode(';', $value);
        $essence = strtolower(trim(array_shift($parts)));
        if (preg_match('~^([a-z0-9!#$&^_.+-]+|\*)/([a-z0-9!#$&^_.+-]+|\*)$~D', $essence, $match) !== 1) {
            return null;
        }
        if ($match[1] === '*' && $match[2] !== '*') {
            return null;
        }

        $charset = null;
        foreach ($parts as $parameter) {
            [$name, $parameterValue] = array_pad(explode('=', $parameter, 2), 2, '');
            if (strtolower(trim($name)) === 'charset') {
                $charset = strtolower(trim(trim($parameterValue), '"'));
            }
        }

        return new self($match[1], $match[2], $charset);
    }

    /** `application/json` and every `+json` suffix (RFC 6839). */
    public function isJson(): bool
    {
        return $this->type === 'application' && ($this->subtype === 'json' || str_ends_with($this->subtype, '+json'));
    }

    /** `application/x-www-form-urlencoded` (WHATWG URL §5): a request body of named strings. */
    public function isForm(): bool
    {
        return $this->type === 'application' && $this->subtype === 'x-www-form-urlencoded';
    }

    /** Whether this range covers `$type`. */
    public function covers(self $type): bool
    {
        return ($this->type === '*' || $this->type === $type->type)
            && ($this->subtype === '*' || $this->subtype === $type->subtype);
    }

    /** 2 for a concrete type, 1 for `type/*`, 0 for `*\/*`: the more specific range wins. */
    public function specificity(): int
    {
        return ($this->type === '*' ? 0 : 1) + ($this->subtype === '*' ? 0 : 1);
    }

    public function essence(): string
    {
        return $this->type . '/' . $this->subtype;
    }
}
