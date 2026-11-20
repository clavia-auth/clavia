<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients;

use Clavia\Domain\Client\Client;

/**
 * A machine client just registered, with the only copy of its secret that will ever
 * exist in the clear: it is stored hashed.
 */
final readonly class RegisteredMachineClient
{
    /**
     * @param bool $secretGenerated Whether the secret was generated rather than chosen by the operator.
     */
    public function __construct(
        public Client $client,
        #[\SensitiveParameter] public string $secret,
        public bool $secretGenerated,
    ) {
    }
}
