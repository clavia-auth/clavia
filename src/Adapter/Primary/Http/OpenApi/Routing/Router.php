<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Routing;

use Clavia\Adapter\Primary\Http\OpenApi\Operation;

/**
 * Finds the operation a method and path are, under the document's server base paths.
 *
 * Methods are exact and case-sensitive (RFC 9110 §9.1): `HEAD` is not `GET`, and
 * `OPTIONS` is nothing unless the document says so. Paths are compared after decoding
 * percent-encoded unreserved characters, and nothing else: no case folding, no dot
 * segments, no trailing-slash leniency. Among templates matching a path, the most
 * specific wins ({@see PathTemplate::compareSpecificity()}).
 */
final readonly class Router
{
    /** @var list<Operation> Most specific first. */
    private array $operations;

    /**
     * @param list<Operation> $operations
     * @param list<string>    $basePaths  Without a trailing `/`; `''` for the root.
     */
    public function __construct(array $operations, private array $basePaths)
    {
        usort(
            $operations,
            static fn (Operation $a, Operation $b): int => $a->path->compareSpecificity($b->path),
        );
        $this->operations = $operations;
    }

    public function match(string $method, string $path): ?RouteMatch
    {
        foreach ($this->candidates($path) as $segments) {
            foreach ($this->operations as $operation) {
                if ($operation->method !== $method) {
                    continue;
                }
                $values = $operation->path->match($segments);
                if ($values !== null) {
                    return new RouteMatch($operation, $values);
                }
            }
        }

        return null;
    }

    /**
     * Whether some operation has this path, whatever its method — a 405 rather than a
     * 404 for a caller that asks.
     */
    public function knowsPath(string $path): bool
    {
        foreach ($this->candidates($path) as $segments) {
            foreach ($this->operations as $operation) {
                if ($operation->path->match($segments) !== null) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Decode the percent-encoded unreserved characters of a segment (RFC 3986 §6.2.2.2):
     * `%7Eme` and `~me` are the same segment; `%2F` stays encoded.
     */
    private static function normalise(string $segment): string
    {
        return preg_replace_callback(
            '/%([0-9A-Fa-f]{2})/',
            static function (array $match): string {
                $character = chr((int) hexdec($match[1]));

                return preg_match('/^[A-Za-z0-9\-._~]$/D', $character) === 1 ? $character : strtoupper($match[0]);
            },
            $segment,
        ) ?? $segment;
    }

    /**
     * The path's segments under each base path it falls under.
     *
     * @return list<list<string>>
     */
    private function candidates(string $path): array
    {
        $candidates = [];
        foreach ($this->basePaths as $base) {
            if ($base !== '' && $path !== $base && ! str_starts_with($path, $base . '/')) {
                continue;
            }
            $rest = substr($path, strlen($base));
            if (str_starts_with($rest, '/')) {
                $candidates[] = array_map(self::normalise(...), explode('/', substr($rest, 1)));
            }
        }

        return $candidates;
    }
}
