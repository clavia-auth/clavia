<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Auth\AuthPageResponder;
use Clavia\Adapter\Primary\Http\Auth\Saml\SamlAcsHandler;
use Clavia\Adapter\Primary\Http\Shared\ErrorResponder;
use Clavia\Application\Authentication\External\Saml\ReceiveSamlResponse;
use Psr\Container\ContainerInterface;

final class SamlAcsHandlerFactory
{
    public function __invoke(ContainerInterface $container): SamlAcsHandler
    {
        /** @var ReceiveSamlResponse $receive */
        $receive = $container->get(ReceiveSamlResponse::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);
        /** @var ErrorResponder $errors */
        $errors = $container->get(ErrorResponder::class);

        return new SamlAcsHandler($receive, $responder, $errors);
    }
}
