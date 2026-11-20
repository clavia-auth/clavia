<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Development;

use Clavia\Domain\Client\ClientId;

/**
 * What {@see SeedDevelopmentData} found or created.
 */
final readonly class SeededDevelopmentData
{
    /**
     * @param non-empty-string $signingKeyId The `kid` of the active signing key.
     */
    public function __construct(
        public string $userEmail,
        public bool $userCreated,
        public ClientId $clientId,
        public bool $clientCreated,
        public string $signingKeyId,
        public bool $signingKeyCreated,
    ) {
    }
}
