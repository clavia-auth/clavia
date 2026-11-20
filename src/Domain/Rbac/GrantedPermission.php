<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Rbac;

use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\Scope;

/**
 * A permission a role grants, named the only unambiguous way: by the API that defines
 * it and its value. `read:users` on two APIs are two permissions.
 *
 * The pair is exactly the key of the API's permission, and storage holds it as a foreign
 * key onto it: when the API stops defining the permission, no role grants it any more.
 */
final readonly class GrantedPermission
{
    public function __construct(
        public ResourceServerId $resourceServerId,
        public Scope $value,
    ) {
    }

    /** One string per permission, for comparing and keying sets of them. */
    public function key(): string
    {
        return $this->resourceServerId->value . ' ' . $this->value->value;
    }
}
