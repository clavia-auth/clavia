<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Routing;

/**
 * A path as the document writes it (`/clients/{client_id}/rotate-secret`), matched
 * segment by segment against a request path.
 *
 * A templated segment matches one non-empty segment; a template may share a segment
 * with literal text (`/files/{name}.json`). Values are percent-decoded once, after
 * matching, so an encoded `/` (`%2F`) stays inside its segment.
 */
final readonly class PathTemplate
{
    /**
     * @param list<string|null>     $literals One per segment: the literal text, or null if templated.
     * @param list<non-empty-string> $patterns One regular expression per segment.
     * @param list<list<string>>    $names    The parameter names each segment captures.
     */
    private function __construct(
        public string $template,
        private array $literals,
        private array $patterns,
        private array $names,
    ) {
    }

    /**
     * @return self|null Null when the template is malformed (an unclosed or empty `{}`,
     *                   a name used twice, two placeholders side by side).
     */
    public static function parse(string $template): ?self
    {
        if (! str_starts_with($template, '/')) {
            return null;
        }

        $literals = $patterns = $names = [];
        $seen = [];
        foreach (explode('/', substr($template, 1)) as $segment) {
            if (! str_contains($segment, '{') && ! str_contains($segment, '}')) {
                $literals[] = $segment;
                $patterns[] = '~^' . preg_quote($segment, '~') . '$~D';
                $names[] = [];
                continue;
            }

            $parts = preg_split('/(\{[^{}\/]*\})/', $segment, -1, PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY);
            $pattern = '';
            $captured = [];
            $previousWasPlaceholder = false;
            foreach ($parts === false ? [] : $parts as $part) {
                if (preg_match('/^\{[^{}\/]*\}$/D', $part) === 1) {
                    $name = substr($part, 1, -1);
                    if ($name === '' || isset($seen[$name]) || $previousWasPlaceholder) {
                        return null;
                    }
                    $seen[$name] = true;
                    $captured[] = $name;
                    $pattern .= '([^/]+?)';
                    $previousWasPlaceholder = true;
                } elseif (str_contains($part, '{') || str_contains($part, '}')) {
                    return null;
                } else {
                    $pattern .= preg_quote($part, '~');
                    $previousWasPlaceholder = false;
                }
            }
            $literals[] = null;
            $patterns[] = '~^' . $pattern . '$~D';
            $names[] = $captured;
        }

        return new self($template, $literals, $patterns, $names);
    }

    /**
     * @return list<string> Every parameter name the template holds, in order.
     */
    public function parameterNames(): array
    {
        return array_merge(...$this->names);
    }

    /**
     * The raw (still percent-encoded) parameter values, when `$segments` matches.
     *
     * @param list<string> $segments The request path after the base path, split on `/`.
     *
     * @return array<string, string>|null
     */
    public function match(array $segments): ?array
    {
        if (count($segments) !== count($this->patterns)) {
            return null;
        }

        $values = [];
        foreach ($this->patterns as $index => $pattern) {
            if (preg_match($pattern, $segments[$index], $match) !== 1) {
                return null;
            }
            foreach ($this->names[$index] as $position => $name) {
                $values[$name] = $match[$position + 1];
            }
        }

        return $values;
    }

    /**
     * Order between two templates that could match the same path: segment by segment from
     * the left, a literal segment wins over a templated one (OpenAPI 3.0 §4.7.8 —
     * concrete paths before templated ones). Negative when this one is more specific.
     */
    public function compareSpecificity(self $other): int
    {
        foreach ($this->literals as $index => $literal) {
            $theirs = $other->literals[$index] ?? null;
            if (($literal === null) !== ($theirs === null)) {
                return $literal === null ? 1 : -1;
            }
        }

        return 0;
    }
}
