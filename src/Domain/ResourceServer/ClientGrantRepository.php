<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\ResourceServer;

use Clavia\Domain\Client\ClientId;

/**
 * What each client holds on each API, as itself.
 *
 * Written only from the shell, never over HTTP: an endpoint that wrote client grants
 * would let its caller widen its own access, which would make every other permission
 * on this server advisory.
 */
interface ClientGrantRepository
{
    public function find(ClientId $client, ResourceServerId $resourceServer): ?ClientGrant;

    /** Record the grant, replacing whatever the client held on that API. */
    public function save(ClientGrant $grant): void;
}
