<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning;

use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Provisioning\ProvisioningToken;

/**
 * Who is calling `/scim/v2`: a directory holding a usable provisioning token, and the connection
 * every account it reaches lives in (docs/design/scim-provisioning.md §7: a token reaches one
 * connection).
 */
final readonly class ProvisioningCaller
{
    public function __construct(
        public ProvisioningToken $token,
        public Connection $connection,
    ) {
    }

    /** How the audit trail names it: the token, never the secret. */
    public function actor(): Actor
    {
        return Actor::provisioning($this->token->id);
    }
}
