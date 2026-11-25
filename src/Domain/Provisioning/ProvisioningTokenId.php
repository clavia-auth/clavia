<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Provisioning;

use Clavia\Domain\Shared\UuidId;

/**
 * Identifies a provisioning token: not the token itself, which is a secret and stored only as its
 * digest. What the Management API and the audit trail name it by.
 */
final readonly class ProvisioningTokenId extends UuidId
{
}
