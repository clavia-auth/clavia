<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Clients\ReadClientLogo;
use Clavia\Domain\Client\ClientLogoRepository;
use Psr\Container\ContainerInterface;

final class ReadClientLogoFactory
{
    public function __invoke(ContainerInterface $container): ReadClientLogo
    {
        /** @var ClientLogoRepository $logos */
        $logos = $container->get(ClientLogoRepository::class);

        return new ReadClientLogo($logos);
    }
}
