<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\PageRequest;

/**
 * The `page`, `per_page` and `q` query parameters every list operation takes, as a
 * {@see PageRequest}. Absent ones take the contract's defaults.
 */
final class Paging
{
    private function __construct()
    {
    }

    /**
     * @throws InvalidValue
     */
    public static function fromQuery(RequestParameters $query): PageRequest
    {
        return PageRequest::of(
            self::integer($query, 'page', 1),
            self::integer($query, 'per_page', 50),
            $query->get('q') ?? '',
        );
    }

    private static function integer(RequestParameters $query, string $name, int $default): int
    {
        $value = $query->get($name);
        if ($value === null) {
            return $default;
        }

        $integer = filter_var($value, FILTER_VALIDATE_INT);

        return $integer === false
            ? throw new InvalidValue(sprintf("'%s' must be an integer.", $name))
            : $integer;
    }
}
