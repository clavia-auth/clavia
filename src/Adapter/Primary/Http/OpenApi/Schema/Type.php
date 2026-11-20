<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Schema;

/**
 * The `type` of an OpenAPI 3.0 Schema Object: one of six, never a list (that is 3.1),
 * and `null` is not one of them (`nullable: true` says it).
 */
enum Type: string
{
    case String = 'string';
    case Number = 'number';
    case Integer = 'integer';
    case Boolean = 'boolean';
    case Array = 'array';
    case Object = 'object';

    /** "a string", "an integer"… for messages. */
    public function described(): string
    {
        return match ($this) {
            self::Integer, self::Array, self::Object => 'an ' . $this->value,
            default => 'a ' . $this->value,
        };
    }
}
