<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Access\AccessContract;

/**
 * Reads the Authorization API's OpenAPI document, the contract every `/access/v1/*` request is
 * checked against. Built only when such a request arrives.
 */
final class AccessContractFactory
{
    public const string DOCUMENT = __DIR__ . '/../../../docs/openapi/authorization-api.yaml';

    public function __invoke(): AccessContract
    {
        return AccessContract::fromFile(self::DOCUMENT);
    }
}
