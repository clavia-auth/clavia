<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc\Keys;

use Clavia\Domain\Oidc\SigningKey;

/**
 * A signing key as `clavia keys:list` reports it.
 */
final readonly class ListedSigningKey
{
    /**
     * @param bool $published Whether the key is in the JWKS right now.
     */
    public function __construct(
        public SigningKey $key,
        public bool $published,
    ) {
    }
}
