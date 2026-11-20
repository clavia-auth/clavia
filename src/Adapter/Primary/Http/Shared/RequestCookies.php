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
 * The cookies a browser sent, read from the `Cookie` header itself.
 *
 * Not from `getCookieParams()`: PHP builds that from `$_COOKIE`, which rewrites names
 * (`a.b` becomes `a_b`) and keeps a single value per name. A browser can hold two
 * cookies of one name at different paths and sends both, most specific path first
 * (RFC 6265 §5.4); which one PHP keeps is not the question to leave to chance.
 */
final class RequestCookies
{
    private function __construct()
    {
    }

    /**
     * Every value sent under `$name`, in the order the browser sent them. Empty values
     * are left out: an empty cookie carries nothing to check.
     *
     * @return list<string>
     */
    public static function all(ServerRequestInterface $request, string $name): array
    {
        $values = [];

        foreach ($request->getHeader('Cookie') as $header) {
            foreach (explode(';', $header) as $pair) {
                $separator = strpos($pair, '=');
                if ($separator === false) {
                    continue;
                }

                $value = trim(substr($pair, $separator + 1));
                if (trim(substr($pair, 0, $separator)) === $name && $value !== '') {
                    $values[] = $value;
                }
            }
        }

        return $values;
    }

    /**
     * The value at the most specific path — the one this server set, when it set one.
     */
    public static function first(ServerRequestInterface $request, string $name): ?string
    {
        return self::all($request, $name)[0] ?? null;
    }
}
