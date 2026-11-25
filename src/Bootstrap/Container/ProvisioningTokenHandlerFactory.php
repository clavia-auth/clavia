<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Adapter\Primary\Http\Management\ProvisioningTokenHandler;
use Clavia\Application\Management\ProvisioningTokens\ReadProvisioningTokens;
use Clavia\Application\Management\ProvisioningTokens\RevokeProvisioningToken;
use Psr\Container\ContainerInterface;

final class ProvisioningTokenHandlerFactory
{
    public function __invoke(ContainerInterface $container): ProvisioningTokenHandler
    {
        /** @var ReadProvisioningTokens $read */
        $read = $container->get(ReadProvisioningTokens::class);
        /** @var RevokeProvisioningToken $revoke */
        $revoke = $container->get(RevokeProvisioningToken::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new ProvisioningTokenHandler($read, $revoke, $responder);
    }
}
