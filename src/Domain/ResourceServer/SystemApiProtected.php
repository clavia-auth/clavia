<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\ResourceServer;

use DomainException;

/**
 * A change that would make a system API — one the server itself depends on — unusable,
 * and with it the means of undoing the change.
 */
final class SystemApiProtected extends DomainException
{
    public static function permissions(ResourceServer $api): self
    {
        return new self(sprintf(
            "The permissions of the system API '%s' are defined by the server itself. "
            . 'Run `clavia management-api:register` to restore them.',
            $api->identifier->value,
        ));
    }

    public static function deletion(ResourceServer $api): self
    {
        return new self(sprintf(
            "The system API '%s' is required by the server itself and cannot be deleted: "
            . 'doing so would revoke the credentials needed to restore it.',
            $api->identifier->value,
        ));
    }
}
