<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

/**
 * Words a page shows, as a key of the catalogue and its values, worded by {@see PageRenderer} in the
 * page's language. A typed value, so a key is never printed as if it were text.
 */
final readonly class Message
{
    /**
     * @param non-empty-string                    $key
     * @param array<non-empty-string, string|int> $values
     */
    private function __construct(
        public string $key,
        public array $values,
    ) {
    }

    /**
     * @param non-empty-string                    $key
     * @param array<non-empty-string, string|int> $values
     */
    public static function of(string $key, array $values = []): self
    {
        return new self($key, $values);
    }
}
