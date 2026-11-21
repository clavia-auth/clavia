<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Adapter\Secondary\IdentityProvider\JwksCache;

/**
 * Key sets in an array — the lifetime is recorded, never waited for: a test that wants an
 * entry gone calls {@see forget()}.
 */
final class InMemoryJwksCache implements JwksCache
{
    /** @var array<string, array{document: string, ttl: positive-int}> By `jwks_uri`. */
    public array $entries = [];

    #[\Override]
    public function get(string $jwksUri): ?string
    {
        return $this->entries[$jwksUri]['document'] ?? null;
    }

    #[\Override]
    public function put(string $jwksUri, string $document, int $ttlSeconds): void
    {
        $this->entries[$jwksUri] = ['document' => $document, 'ttl' => $ttlSeconds];
    }

    public function forget(string $jwksUri): void
    {
        unset($this->entries[$jwksUri]);
    }
}
