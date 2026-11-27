<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Auth\AuthCookies;
use Clavia\Adapter\Primary\Http\Auth\AuthPageResponder;
use Clavia\Adapter\Primary\Http\Shared\PageRenderer;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final class AuthPageResponderFactory
{
    public function __invoke(ContainerInterface $container): AuthPageResponder
    {
        /** @var PageRenderer $pages */
        $pages = $container->get(PageRenderer::class);
        /** @var ResponseFactoryInterface $responses */
        $responses = $container->get(ResponseFactoryInterface::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new AuthPageResponder($pages, $responses, $secrets, $cookies, $settings->issuer());
    }
}
