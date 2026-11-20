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
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\ScopeSet;

/**
 * What {@see SeedManagementAccess} found or created. The machine client's secret is
 * {@see SeedManagementAccess::CLIENT_SECRET}.
 */
final readonly class SeededManagementAccess
{
    public function __construct(
        public Audience $managementApi,
        public ClientId $clientId,
        public bool $clientCreated,
        public ScopeSet $scopes,
    ) {
    }
}
