<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc\Keys;

use Clavia\Application\Port\SigningKeyStore;
use Clavia\Domain\Oidc\SigningKey;
use Clavia\Domain\Shared\Clock;

/**
 * Every signing key, newest first, with its place in the rotation: `clavia keys:list`.
 */
final readonly class ListSigningKeys
{
    public function __construct(
        private SigningKeyStore $keys,
        private Clock $clock,
    ) {
    }

    /** @return list<ListedSigningKey> */
    public function __invoke(): array
    {
        $now = $this->clock->now();

        return array_map(
            static fn (SigningKey $key): ListedSigningKey => new ListedSigningKey($key, $key->isPublishedAt($now)),
            $this->keys->all(),
        );
    }
}
