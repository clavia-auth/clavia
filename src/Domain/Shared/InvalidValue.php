<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Shared;

use InvalidArgumentException;

/**
 * A value object was asked to hold something it cannot represent.
 *
 * Thrown by named constructors, so an instance that exists is always valid. The
 * message describes the rule that was broken and is safe to log; whether any of it is
 * shown to a client is the driving adapter's decision.
 */
final class InvalidValue extends InvalidArgumentException
{
}
