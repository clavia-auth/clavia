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
use Clavia\Adapter\Primary\Http\Management\ProvisioningTokensHandler;
use Clavia\Application\Management\ProvisioningTokens\IssueProvisioningToken;
use Clavia\Application\Management\ProvisioningTokens\ReadProvisioningTokens;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class ProvisioningTokensHandlerFactory
{
    public function __invoke(ContainerInterface $container): ProvisioningTokensHandler
    {
        /** @var ReadProvisioningTokens $read */
        $read = $container->get(ReadProvisioningTokens::class);
        /** @var IssueProvisioningToken $issue */
        $issue = $container->get(IssueProvisioningToken::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new ProvisioningTokensHandler($read, $issue, $responder, $settings->scimBaseUrl());
    }
}
