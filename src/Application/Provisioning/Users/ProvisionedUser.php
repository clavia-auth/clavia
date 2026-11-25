<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning\Users;

use Clavia\Domain\Identity\User;
use Clavia\Domain\Provisioning\ProvisionedAccount;

/** An account a directory provisioned, with what SCIM knows it by: what a `User` resource shows. */
final readonly class ProvisionedUser
{
    public function __construct(
        public User $user,
        public ProvisionedAccount $account,
    ) {
    }
}
