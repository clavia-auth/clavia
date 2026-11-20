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
 * One Security Requirement Object (OpenAPI 3.0 §4.7.30): the schemes that must *all* be
 * satisfied, each with the scopes it needs. An operation lists alternatives; any one
 * requirement satisfied is enough.
 */
final readonly class SecurityRequirement
{
    /**
     * @param array<string, list<string>> $scopes By security scheme name.
     */
    public function __construct(public array $scopes)
    {
    }

    /**
     * The scopes this requirement names for `$scheme`; null when it does not use it.
     *
     * @return list<string>|null
     */
    public function scopesFor(string $scheme): ?array
    {
        return $this->scopes[$scheme] ?? null;
    }
}
