<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Cli\IssueRegistrationTokenCommand;
use Clavia\Application\Management\InitialAccessTokens\IssueInitialAccessToken;
use Clavia\Configuration\ClientRegistration;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class IssueRegistrationTokenCommandFactory
{
    public function __invoke(ContainerInterface $container): IssueRegistrationTokenCommand
    {
        /** @var IssueInitialAccessToken $issue */
        $issue = $container->get(IssueInitialAccessToken::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new IssueRegistrationTokenCommand($issue, $settings->clientRegistration === ClientRegistration::Token);
    }
}
