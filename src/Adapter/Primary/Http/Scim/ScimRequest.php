<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Clavia\Application\Provisioning\ProvisioningCaller;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The directory a `/scim/v2` request comes from, attached by {@see ProvisioningMiddleware}: a
 * handler reads it, and every account it reaches is in the caller's connection.
 */
final class ScimRequest
{
    private const string ATTRIBUTE = ProvisioningCaller::class;

    private function __construct()
    {
    }

    public static function attach(ServerRequestInterface $request, ProvisioningCaller $caller): ServerRequestInterface
    {
        return $request->withAttribute(self::ATTRIBUTE, $caller);
    }

    public static function caller(ServerRequestInterface $request): ProvisioningCaller
    {
        $caller = $request->getAttribute(self::ATTRIBUTE);
        if (! $caller instanceof ProvisioningCaller) {
            throw new LogicException('A SCIM handler routed without the provisioning middleware.');
        }

        return $caller;
    }
}
