<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Whether a request comes from someone reading pages, or from a program reading data.
 *
 * Decided from `Accept` (RFC 9110 §12.5.1). A browser navigating to a page asks for
 * `text/html` by name; a program asks for `application/json`, for `*\/*`, or for nothing.
 * So a request prefers HTML only when it names HTML — exactly, or as `text/*` — with a
 * weight above zero and at least as high as the one it gives JSON. Anything else,
 * including no `Accept` at all, gets the machine-readable answer: that is what every
 * existing client of this server expects, and a program never has to opt out.
 */
final class ClientPreference
{
    private function __construct()
    {
    }

    public static function prefersHtml(ServerRequestInterface $request): bool
    {
        $ranges = self::ranges($request->getHeaderLine('Accept'));

        // HTML counts only when named — `*/*` alone is how programs say "anything" — and
        // `application/*` names JSON's family, not XHTML's.
        $html = max(
            self::weight($ranges, 'text', 'html', typeWildcard: true, anyWildcard: false),
            self::weight($ranges, 'application', 'xhtml+xml', typeWildcard: false, anyWildcard: false),
        );
        $json = self::weight($ranges, 'application', 'json', typeWildcard: true, anyWildcard: true);

        return $html > 0.0 && $html >= $json;
    }

    /**
     * @return list<array{type: string, subtype: string, q: float}>
     */
    private static function ranges(string $accept): array
    {
        $ranges = [];

        foreach (explode(',', $accept) as $range) {
            $parameters = array_map(trim(...), explode(';', $range));
            $mediaRange = strtolower(array_shift($parameters));
            if (preg_match('#^([a-z0-9!\#$&^_.+*-]+)/([a-z0-9!\#$&^_.+*-]+)$#D', $mediaRange, $match) !== 1) {
                continue;
            }

            $q = 1.0;
            foreach ($parameters as $parameter) {
                if (preg_match('/^q\s*=/i', $parameter) !== 1) {
                    continue;
                }

                // RFC 9110 §12.4.2: a weight is 0 to 1 with at most three decimals. A range
                // with any other weight says nothing reliable and is left out.
                if (preg_match('/^q\s*=\s*(0(?:\.\d{0,3})?|1(?:\.0{0,3})?)$/Di', $parameter, $weight) !== 1) {
                    continue 2;
                }

                $q = (float) $weight[1];
            }

            $ranges[] = ['type' => $match[1], 'subtype' => $match[2], 'q' => $q];
        }

        return $ranges;
    }

    /**
     * The weight the most specific matching range gives a media type (RFC 9110 §12.5.1);
     * zero when none matches.
     *
     * @param list<array{type: string, subtype: string, q: float}> $ranges
     */
    private static function weight(
        array $ranges,
        string $type,
        string $subtype,
        bool $typeWildcard,
        bool $anyWildcard,
    ): float {
        $best = null;
        $bestSpecificity = -1;

        foreach ($ranges as $range) {
            $specificity = match (true) {
                $range['type'] === $type && $range['subtype'] === $subtype => 2,
                $typeWildcard && $range['type'] === $type && $range['subtype'] === '*' => 1,
                $anyWildcard && $range['type'] === '*' && $range['subtype'] === '*' => 0,
                default => -1,
            };

            if ($specificity > $bestSpecificity) {
                $best = $range['q'];
                $bestSpecificity = $specificity;
            }
        }

        return $best ?? 0.0;
    }
}
