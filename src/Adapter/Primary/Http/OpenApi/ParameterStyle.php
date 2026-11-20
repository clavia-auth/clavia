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
 * How an array parameter is serialised (OpenAPI 3.0 §4.7.12.2). Primitive values look
 * the same in every style this validator supports.
 *
 * Supported: `simple` (`a,b`) for paths and headers, `form` for queries and cookies —
 * exploded (`?id=a&id=b`) or not (`?id=a,b`). `matrix`, `label`, `spaceDelimited`,
 * `pipeDelimited` and `deepObject`, and object-valued parameters, are refused when the
 * document is loaded.
 */
enum ParameterStyle: string
{
    case Simple = 'simple';
    case Form = 'form';

    public static function defaultFor(ParameterLocation $location): self
    {
        return match ($location) {
            ParameterLocation::Path, ParameterLocation::Header => self::Simple,
            ParameterLocation::Query, ParameterLocation::Cookie => self::Form,
        };
    }
}
