<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Mfa\DescribeSecondFactorPage;
use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Domain\Client\ClientRepository;
use Psr\Container\ContainerInterface;

final class DescribeSecondFactorPageFactory
{
    public function __invoke(ContainerInterface $container): DescribeSecondFactorPage
    {
        /** @var MfaChallengeStore $challenges */
        $challenges = $container->get(MfaChallengeStore::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);

        return new DescribeSecondFactorPage($challenges, $clients);
    }
}
