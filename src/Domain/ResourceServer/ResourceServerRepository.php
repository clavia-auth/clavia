<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\ResourceServer;

use Clavia\Domain\Shared\Audience;

/**
 * The registered APIs.
 */
interface ResourceServerRepository
{
    public function find(ResourceServerId $id): ?ResourceServer;

    /** The API whose identifier is exactly `$identifier` — the `audience` a client names. */
    public function findByIdentifier(Audience $identifier): ?ResourceServer;

    /** Create the API, or replace its name and permissions. The identifier never changes. */
    public function save(ResourceServer $resourceServer): void;
}
