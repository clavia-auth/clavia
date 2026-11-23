<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Clavia\Application\OAuth2\ProtectedResource\PresentedCredentials;
use Clavia\Application\OAuth2\ProtectedResource\TokenScheme;
use Clavia\Domain\OAuth2\BearerTokenError;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Reads the access token a request presents to a protected resource: `Authorization: Bearer`
 * (RFC 6750 §2.1) or `Authorization: DPoP` with its `DPoP` proof header (RFC 9449 §7.1).
 *
 * Only the `Authorization` header is a way in: tokens in a form body or a query string
 * (RFC 6750 §2.2, §2.3) end up in logs, histories and `Referer` headers, and OAuth 2.1 drops the
 * query form outright. Whether the scheme suits the token is the application's
 * ({@see \Clavia\Application\OAuth2\ProtectedResource\CheckSenderConstraint}).
 */
final class AccessTokenCredentials
{
    /** `Bearer` or `DPoP`, 1*SP, a token68 (RFC 9110 §11.2), the scheme case-insensitive. */
    private const string PATTERN = '/^(Bearer|DPoP) +([A-Za-z0-9\-._~+\/]+=*)$/Di';

    private function __construct()
    {
    }

    /**
     * @return PresentedCredentials|null Null when the request carries no access token at all — no
     *                                   `Authorization` header, or one of another scheme.
     *
     * @throws BearerTokenError `invalid_request` for a malformed header, more than one `Authorization`
     *                          header, or a token also sent another way (RFC 6750 §2: one method).
     */
    public static function fromRequest(ServerRequestInterface $request): ?PresentedCredentials
    {
        $headers = $request->getHeader('Authorization');
        if ($headers === []) {
            return null;
        }
        if (count($headers) > 1) {
            throw BearerTokenError::invalidRequest("More than one 'Authorization' header.");
        }

        $header = $headers[0];
        if (preg_match('/^(Bearer|DPoP)(?: |$)/i', $header) !== 1) {
            return null;
        }

        if (preg_match(self::PATTERN, $header, $match) !== 1 || $match[2] === '') {
            throw BearerTokenError::invalidRequest("Malformed 'Authorization' header.");
        }

        if (
            RequestParameterReader::query($request)->get('access_token') !== null
            || RequestParameterReader::form($request)->get('access_token') !== null
        ) {
            throw BearerTokenError::invalidRequest('The access token was sent in more than one way.');
        }

        return strcasecmp($match[1], 'DPoP') === 0
            ? new PresentedCredentials(TokenScheme::Dpop, $match[2], array_values($request->getHeader('DPoP')))
            : PresentedCredentials::bearer($match[2]);
    }
}
