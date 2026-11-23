<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use Clavia\Domain\Client\ClientId;

/**
 * An authorization request a client pushed to `/oauth2/par` (RFC 9126), held until the browser
 * brings its `request_uri` to the authorization endpoint.
 *
 * The parameters are the request: the authorization endpoint reads them instead of its query,
 * which then carries only `client_id` and `request_uri` (§4). They travel from the client to
 * this server over an authenticated back channel, so they are neither visible in the browser
 * nor open to change on the way.
 *
 * The `request_uri` is a URN naming a random handle, which is stored as its digest.
 */
final readonly class PushedAuthorizationRequest
{
    /** The prefix of every `request_uri` this server hands out (RFC 9126 §2.2). */
    public const string URN_PREFIX = 'urn:ietf:params:oauth:request_uri:';

    /**
     * @param list<array{string, string}> $parameters Every parameter, name and value, in order; never the
     *                                                client's credentials.
     */
    public function __construct(
        public ClientId $clientId,
        public array $parameters,
    ) {
    }

    /** The `request_uri` for a handle. */
    public static function uriFor(#[\SensitiveParameter] string $handle): string
    {
        return self::URN_PREFIX . $handle;
    }

    /** The handle a `request_uri` names; null for one this server did not hand out. */
    public static function handleOf(string $requestUri): ?string
    {
        if (! str_starts_with($requestUri, self::URN_PREFIX)) {
            return null;
        }
        $handle = substr($requestUri, strlen(self::URN_PREFIX));

        return preg_match('/^[A-Za-z0-9_-]{43}$/D', $handle) === 1 ? $handle : null;
    }
}
