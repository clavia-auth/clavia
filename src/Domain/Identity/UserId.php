<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

use Clavia\Domain\Shared\UuidId;

/**
 * Identifies an end user, and is the OIDC `sub` claim: stable and opaque.
 *
 * Never the email address — emails change hands, and OIDC Core §2 requires `sub` never
 * to be reassigned.
 */
final readonly class UserId extends UuidId
{
}
