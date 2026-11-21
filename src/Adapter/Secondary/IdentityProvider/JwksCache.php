<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\IdentityProvider;

/**
 * The signing keys of upstream OpenID providers, as last fetched, by `jwks_uri`.
 *
 * Kept as the raw JSON the provider published: it is parsed where it is used, and what
 * a provider publishes is the provider's business until then.
 */
interface JwksCache
{
    public function get(string $jwksUri): ?string;

    /**
     * @param positive-int $ttlSeconds
     */
    public function put(string $jwksUri, string $document, int $ttlSeconds): void;
}
