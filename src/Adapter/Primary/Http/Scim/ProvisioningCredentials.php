<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Reads the provisioning token a directory presents: `Authorization: Bearer` (RFC 6750 §2.1), the
 * one way directories send it (Entra ID's "Secret Token", Okta's HTTP header authentication).
 *
 * Stricter than a protected resource's reader, on purpose: no DPoP, no token in a query or a form,
 * one header. Whatever else arrives is no token, and gets the same `401` as a wrong one.
 */
final class ProvisioningCredentials
{
    /** `Bearer`, 1*SP, a token68 (RFC 9110 §11.2), the scheme case-insensitive. */
    private const string PATTERN = '/^Bearer +([A-Za-z0-9\-._~+\/]+=*)$/Di';

    private function __construct()
    {
    }

    /** Whether the request carries an `Authorization` header at all: a token was presented. */
    public static function presented(ServerRequestInterface $request): bool
    {
        return $request->getHeader('Authorization') !== [];
    }

    /**
     * @return non-empty-string|null The token; null when there is none, or more than one header, or
     *                               another scheme, or a malformed one.
     */
    public static function fromRequest(ServerRequestInterface $request): ?string
    {
        $headers = $request->getHeader('Authorization');
        if (count($headers) !== 1 || preg_match(self::PATTERN, $headers[0], $match) !== 1 || $match[1] === '') {
            return null;
        }

        return $match[1];
    }
}
