<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Clients;

/**
 * Changes to a client's registration; null leaves a field alone. The type is not among
 * them: switching between public and confidential is a different client.
 */
final readonly class ClientChanges
{
    /**
     * @param list<string>|null $redirectUris
     * @param list<string>|null $grantTypes
     * @param list<string>|null $responseTypes
     */
    public function __construct(
        public ?string $name = null,
        public ?string $authMethod = null,
        public ?array $redirectUris = null,
        public ?array $grantTypes = null,
        public ?array $responseTypes = null,
    ) {
    }
}
