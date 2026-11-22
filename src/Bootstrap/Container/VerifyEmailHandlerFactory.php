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
use Clavia\Adapter\Primary\Http\Auth\VerifyEmailHandler;
use Clavia\Application\Authentication\Account\ConfirmEmail;
use Clavia\Application\Authentication\Account\DescribeAccountLink;
use Psr\Container\ContainerInterface;

final class VerifyEmailHandlerFactory
{
    public function __invoke(ContainerInterface $container): VerifyEmailHandler
    {
        /** @var DescribeAccountLink $describe */
        $describe = $container->get(DescribeAccountLink::class);
        /** @var ConfirmEmail $confirm */
        $confirm = $container->get(ConfirmEmail::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);

        return new VerifyEmailHandler($describe, $confirm, $responder);
    }
}
