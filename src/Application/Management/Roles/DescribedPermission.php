<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Roles;

use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\Audience;

/**
 * A permission a role grants, with what a person needs to read it: which API it is on —
 * by id and by identifier — and what it allows, in the API's own words.
 */
final readonly class DescribedPermission
{
    public function __construct(
        public ResourceServerId $resourceServerId,
        public Audience $resourceServerIdentifier,
        public string $value,
        public string $description,
    ) {
    }
}
