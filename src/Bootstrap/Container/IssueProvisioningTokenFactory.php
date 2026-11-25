<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\ProvisioningTokens\IssueProvisioningToken;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Provisioning\ProvisioningTokenRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class IssueProvisioningTokenFactory
{
    public function __invoke(ContainerInterface $container): IssueProvisioningToken
    {
        /** @var ProvisioningTokenRepository $tokens */
        $tokens = $container->get(ProvisioningTokenRepository::class);
        /** @var ConnectionRepository $connections */
        $connections = $container->get(ConnectionRepository::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new IssueProvisioningToken($tokens, $connections, $secrets, $random, $clock, $events);
    }
}
