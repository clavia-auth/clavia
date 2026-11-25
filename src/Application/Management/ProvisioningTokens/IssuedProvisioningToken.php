<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ProvisioningTokens;

use Clavia\Domain\Provisioning\ProvisioningToken;

/**
 * A provisioning token just issued, with its secret: the one time the secret exists outside the
 * caller's hands. Only its digest is stored.
 */
final readonly class IssuedProvisioningToken
{
    /** @param non-empty-string $secret */
    public function __construct(
        public ProvisioningToken $token,
        #[\SensitiveParameter] public string $secret,
    ) {
    }
}
