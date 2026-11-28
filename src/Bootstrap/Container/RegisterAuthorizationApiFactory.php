<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Provisioning\RegisterAuthorizationApi;
use Clavia\Application\Management\Provisioning\SystemApiRegistration;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\Audience;
use Psr\Container\ContainerInterface;

final class RegisterAuthorizationApiFactory
{
    public function __invoke(ContainerInterface $container): RegisterAuthorizationApi
    {
        /** @var SystemApiRegistration $registration */
        $registration = $container->get(SystemApiRegistration::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new RegisterAuthorizationApi($registration, Audience::fromString($settings->authorizationApiAudience()));
    }
}
