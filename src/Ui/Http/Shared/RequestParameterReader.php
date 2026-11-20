<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Ui\Http\Shared;

use Clavia\Application\OAuth2\RequestParameters;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Reads the parameters of a request without losing repetitions.
 *
 * PHP's own parsing (`$_GET`, `parse_str()`) keeps the last of two `redirect_uri`
 * values and silently drops the first; the OAuth endpoints must see both to refuse the
 * request (RFC 6749 §3.1). So the query string and the form body are split here, by
 * hand, into every value given for each name.
 */
final class RequestParameterReader
{
    private const string FORM_MEDIA_TYPE = 'application/x-www-form-urlencoded';

    private function __construct()
    {
    }

    /** The query-string parameters. */
    public static function query(ServerRequestInterface $request): RequestParameters
    {
        return self::collect(self::pairs($request->getUri()->getQuery()));
    }

    /**
     * The parameters of a form body; empty unless the body is declared as
     * `application/x-www-form-urlencoded`, the only encoding the OAuth endpoints accept
     * (RFC 6749 §3.2, Appendix B).
     */
    public static function form(ServerRequestInterface $request): RequestParameters
    {
        return self::collect(self::formPairs($request));
    }

    /**
     * Query string and form body together, for an endpoint that accepts its parameters
     * either way. A name present in both counts as repeated.
     */
    public static function queryAndForm(ServerRequestInterface $request): RequestParameters
    {
        return self::collect([...self::pairs($request->getUri()->getQuery()), ...self::formPairs($request)]);
    }

    /**
     * @return list<array{string, string}>
     */
    private static function formPairs(ServerRequestInterface $request): array
    {
        $mediaType = strtolower(trim(explode(';', $request->getHeaderLine('Content-Type'), 2)[0]));

        return $mediaType === self::FORM_MEDIA_TYPE ? self::pairs((string) $request->getBody()) : [];
    }

    /**
     * @return list<array{string, string}> Each name with one of its values, in the order sent.
     */
    private static function pairs(string $encoded): array
    {
        $pairs = [];

        foreach (explode('&', $encoded) as $pair) {
            if ($pair === '') {
                continue;
            }

            [$name, $value] = explode('=', $pair, 2) + [1 => ''];
            $pairs[] = [urldecode($name), urldecode($value)];
        }

        return $pairs;
    }

    /**
     * @param list<array{string, string}> $pairs
     */
    private static function collect(array $pairs): RequestParameters
    {
        $values = [];
        foreach ($pairs as [$name, $value]) {
            $values[$name][] = $value;
        }

        return new RequestParameters($values);
    }
}
