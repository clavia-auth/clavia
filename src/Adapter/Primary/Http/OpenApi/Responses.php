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
 * The responses an operation describes, by status: an exact code, a range (`4XX`), or
 * `default`, matched in that order (OpenAPI 3.0 §4.7.16).
 */
final readonly class Responses
{
    /**
     * @param array<array-key, Response> $byStatus `'200'` (an integer key, once PHP has its way),
     *                                            `'4XX'`, `'default'` — for lookup only.
     */
    public function __construct(private array $byStatus)
    {
    }

    public function for(int $status): ?Response
    {
        return $this->byStatus[(string) $status]
            ?? $this->byStatus[intdiv($status, 100) . 'XX']
            ?? $this->byStatus['default']
            ?? null;
    }
}
