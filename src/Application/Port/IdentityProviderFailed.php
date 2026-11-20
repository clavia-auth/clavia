<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use RuntimeException;

/**
 * An external provider did not complete the exchange: it could not be reached, refused
 * the code, or answered something unusable. The message is for the log; a person is
 * told only that the sign-in did not complete.
 */
final class IdentityProviderFailed extends RuntimeException
{
}
