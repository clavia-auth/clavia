<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Validation;

/**
 * A query string read as `application/x-www-form-urlencoded` (WHATWG URL §5.1), keeping
 * every repetition and every name exactly as sent — unlike `parse_str()`, which keeps
 * the last value and rewrites `a.b` to `a_b` and `a[]` to an array.
 */
final readonly class QueryString
{
    /**
     * @param array<string, array{name: string, values: list<string>}> $parameters Keyed for lookup only.
     */
    private function __construct(private array $parameters)
    {
    }

    /**
     * @return self|null Null when a name or value is not valid UTF-8 once decoded.
     */
    public static function parse(string $query): ?self
    {
        $parameters = [];
        foreach ($query === '' ? [] : explode('&', $query) as $pair) {
            if ($pair === '') {
                continue;
            }
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $name = rawurldecode(str_replace('+', ' ', $name));
            $value = rawurldecode(str_replace('+', ' ', $value));
            if (! mb_check_encoding($name, 'UTF-8') || ! mb_check_encoding($value, 'UTF-8')) {
                return null;
            }

            $key = 'q:' . $name;
            $parameters[$key] ??= ['name' => $name, 'values' => []];
            $parameters[$key]['values'][] = $value;
        }

        return new self($parameters);
    }

    /**
     * Every value sent for `$name`, in order; empty when it was not sent.
     *
     * @return list<string>
     */
    public function values(string $name): array
    {
        return $this->parameters['q:' . $name]['values'] ?? [];
    }

    /**
     * @return list<string> Every name sent, once each.
     */
    public function names(): array
    {
        return array_values(array_map(
            static fn (array $parameter): string => $parameter['name'],
            $this->parameters,
        ));
    }
}
