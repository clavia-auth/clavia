<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Adapter\Secondary\Signing\Remote\PublicKeyCache;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;

final class InMemoryPublicKeyCache implements PublicKeyCache
{
    /** @var array<string, PublicJwk> */
    public array $keys = [];

    #[\Override]
    public function get(string $reference, SigningAlgorithm $algorithm): ?PublicJwk
    {
        return $this->keys[$algorithm->value . ' ' . $reference] ?? null;
    }

    #[\Override]
    public function put(string $reference, PublicJwk $key): void
    {
        $this->keys[$key->algorithm->value . ' ' . $reference] = $key;
    }
}
