<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Remote;

use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;

/**
 * The public halves of remote keys, as last read from their providers, by reference.
 *
 * Safe to keep because a reference names one immutable key version — an alias that
 * could be repointed is refused when the key is configured — so its public half never
 * changes. Kept because without it every token issued, and every JWKS served, would be a
 * round trip to the provider.
 */
interface PublicKeyCache
{
    public function get(string $reference, SigningAlgorithm $algorithm): ?PublicJwk;

    public function put(string $reference, PublicJwk $key): void;
}
