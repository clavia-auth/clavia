<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Clavia\Domain\OAuth2\BearerTokenError;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Reads the bearer token a request presents to a protected resource (RFC 6750 §2.1).
 *
 * Only the `Authorization` header is a way in: tokens in a form body or a query string
 * (§2.2, §2.3) end up in logs, histories and `Referer` headers, and OAuth 2.1 drops the
 * query form outright.
 */
final class BearerCredentials
{
    /** RFC 6750 §2.1: `Bearer` 1*SP b64token, the scheme case-insensitive (RFC 9110 §11.1). */
    private const string PATTERN = '/^Bearer +([A-Za-z0-9\-._~+\/]+=*)$/Di';

    private function __construct()
    {
    }

    /**
     * @return non-empty-string|null The token; null when the request carries no bearer credentials
     *                               at all — no `Authorization` header, or one of another scheme.
     *
     * @throws BearerTokenError `invalid_request` for a malformed `Bearer` header, more than one
     *                          `Authorization` header, or a token also sent another way
     *                          (RFC 6750 §2: one method per request).
     */
    public static function fromRequest(ServerRequestInterface $request): ?string
    {
        $headers = $request->getHeader('Authorization');
        if ($headers === []) {
            return null;
        }
        if (count($headers) > 1) {
            throw BearerTokenError::invalidRequest("More than one 'Authorization' header.");
        }

        $header = $headers[0];
        if (preg_match('/^Bearer(?: |$)/i', $header) !== 1) {
            return null;
        }

        if (preg_match(self::PATTERN, $header, $match) !== 1 || $match[1] === '') {
            throw BearerTokenError::invalidRequest("Malformed 'Authorization: Bearer' header.");
        }

        if (
            RequestParameterReader::query($request)->get('access_token') !== null
            || RequestParameterReader::form($request)->get('access_token') !== null
        ) {
            throw BearerTokenError::invalidRequest('The access token was sent in more than one way.');
        }

        return $match[1];
    }
}
