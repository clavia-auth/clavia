<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management;

use RuntimeException;

/**
 * The resource a Management API operation names does not exist.
 */
final class NotFound extends RuntimeException
{
    public static function of(string $what): self
    {
        return new self(sprintf('No such %s.', $what));
    }
}
