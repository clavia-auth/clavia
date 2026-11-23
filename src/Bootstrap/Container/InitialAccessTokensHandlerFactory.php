<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Management\InitialAccessTokensHandler;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Application\Management\InitialAccessTokens\IssueInitialAccessToken;
use Clavia\Application\Management\InitialAccessTokens\ReadInitialAccessTokens;
use Psr\Container\ContainerInterface;

final class InitialAccessTokensHandlerFactory
{
    public function __invoke(ContainerInterface $container): InitialAccessTokensHandler
    {
        /** @var ReadInitialAccessTokens $read */
        $read = $container->get(ReadInitialAccessTokens::class);
        /** @var IssueInitialAccessToken $issue */
        $issue = $container->get(IssueInitialAccessToken::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new InitialAccessTokensHandler($read, $issue, $responder);
    }
}
