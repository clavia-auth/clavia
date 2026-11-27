<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;

/**
 * Where a client starts a sign-in of its own: `initiate_login_uri` (OpenID Connect Dynamic Client
 * Registration 1.0 §2, OpenID Connect Core 1.0 §4, third-party initiated login). Auth0 calls it the
 * application's login URI.
 *
 * This server sends a person there when the request they were signing in for has expired (#219):
 * only the application can start a new one, and once the request is gone no redirect URI is known to
 * be the right one. It is the operator's to register, never a requester's, so it cannot be turned
 * into an open redirect.
 */
final readonly class InitiateLoginUri
{
    private function __construct(public Url $uri)
    {
    }

    /**
     * @throws InvalidValue When it is not an https URL (Registration §2: "MUST use the https scheme"), or
     *                      has a fragment, which would swallow the `iss` appended to it.
     */
    public static function fromString(string $value): self
    {
        $uri = Url::fromString($value);
        if (! $uri->isHttps()) {
            throw new InvalidValue('A sign-in start address (initiate_login_uri) must be an https URL.');
        }
        if ($uri->hasFragment()) {
            throw new InvalidValue('A sign-in start address (initiate_login_uri) must not contain a fragment.');
        }

        return new self($uri);
    }

    /**
     * The address to send the browser to, with the `iss` Core §4 requires: this server's issuer, so the
     * client knows which provider to start the sign-in with. Appended to the registered address, never
     * parsed and rebuilt, as a redirect URI is.
     */
    public function forIssuer(string $issuer): string
    {
        return $this->uri->value
            . ($this->uri->hasQuery() ? '&' : '?')
            . http_build_query(['iss' => $issuer], '', '&', PHP_QUERY_RFC3986);
    }

    public function equals(self $other): bool
    {
        return $this->uri->equals($other->uri);
    }
}
