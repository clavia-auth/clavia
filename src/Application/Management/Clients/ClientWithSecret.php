<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Clients;

use Clavia\Domain\Client\Client;

/**
 * A client just registered or given a new secret, with the only plain copy of that
 * secret there will ever be. Null for a public client, which has none.
 */
final readonly class ClientWithSecret
{
    public function __construct(
        public Client $client,
        #[\SensitiveParameter] public ?string $secret,
    ) {
    }
}
