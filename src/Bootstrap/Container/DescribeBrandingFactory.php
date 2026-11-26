<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Branding\DescribeBranding;
use Clavia\Domain\Client\ClientLogoRepository;
use Clavia\Domain\Client\ClientRepository;
use Psr\Container\ContainerInterface;

final class DescribeBrandingFactory
{
    public function __invoke(ContainerInterface $container): DescribeBranding
    {
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var ClientLogoRepository $logos */
        $logos = $container->get(ClientLogoRepository::class);

        return new DescribeBranding($clients, $logos);
    }
}
