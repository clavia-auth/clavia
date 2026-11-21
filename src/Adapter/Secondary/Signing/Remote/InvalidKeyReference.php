<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Remote;

use InvalidArgumentException;

/**
 * A key reference a remote backend cannot use: malformed, or naming something that
 * could change under it — an alias, a key without its version.
 */
final class InvalidKeyReference extends InvalidArgumentException
{
}
