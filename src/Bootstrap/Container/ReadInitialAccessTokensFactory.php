<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\InitialAccessTokens\ReadInitialAccessTokens;
use Clavia\Domain\Client\Registration\InitialAccessTokenRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class ReadInitialAccessTokensFactory
{
    public function __invoke(ContainerInterface $container): ReadInitialAccessTokens
    {
        /** @var InitialAccessTokenRepository $tokens */
        $tokens = $container->get(InitialAccessTokenRepository::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new ReadInitialAccessTokens($tokens, $clock);
    }
}
