<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Claims;

use RuntimeException;

/**
 * The custom claims of one token would pass {@see CustomClaims::MAX_BYTES}: the token is refused,
 * never cut down, since a shortened list of roles would be a different, wrong answer. Thrown inside
 * issuance, so nothing is spent; reaching it takes hundreds of roles.
 */
final class CustomClaimsTooLarge extends RuntimeException
{
}
