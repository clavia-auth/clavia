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
use Clavia\Adapter\Primary\Http\Management\SigningKeysHandler;
use Clavia\Application\Oidc\Keys\ListSigningKeys;
use Clavia\Application\Oidc\Keys\RotateSigningKey;
use Clavia\Bootstrap\SigningBackend;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

/**
 * The use cases only for the `postgres` backend: the key store refuses to exist for any other,
 * and the handler answers `409` without them.
 */
final class SigningKeysHandlerFactory
{
    public function __invoke(ContainerInterface $container): SigningKeysHandler
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $managed = SigningBackend::managesItsKeys($settings);
        /** @var ListSigningKeys|null $list */
        $list = $managed ? $container->get(ListSigningKeys::class) : null;
        /** @var RotateSigningKey|null $rotate */
        $rotate = $managed ? $container->get(RotateSigningKey::class) : null;
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new SigningKeysHandler($list, $rotate, $responder);
    }
}
