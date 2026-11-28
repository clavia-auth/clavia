<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

use Clavia\Application\Port\ModelPage;
use Clavia\Domain\Authorization\AuthorizationModelId;

/**
 * A page of an API's model versions, and which one is in force.
 */
final readonly class ModelVersions
{
    public function __construct(
        public AuthorizationModelId $inForce,
        public ModelPage $page,
    ) {
    }
}
