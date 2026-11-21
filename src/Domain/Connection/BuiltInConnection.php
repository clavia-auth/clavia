<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection;

use DomainException;

/**
 * A change only the code may make to one of its own connections.
 */
final class BuiltInConnection extends DomainException
{
    public static function deletion(Connection $connection): self
    {
        return new self(sprintf(
            "The connection '%s' is built in: switch it off rather than deleting it.",
            $connection->name->value,
        ));
    }
}
