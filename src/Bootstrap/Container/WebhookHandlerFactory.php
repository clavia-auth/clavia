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
use Clavia\Adapter\Primary\Http\Management\WebhookHandler;
use Clavia\Application\Management\Webhooks\DeleteWebhook;
use Clavia\Application\Management\Webhooks\ReadWebhooks;
use Clavia\Application\Management\Webhooks\UpdateWebhook;
use Psr\Container\ContainerInterface;

final class WebhookHandlerFactory
{
    public function __invoke(ContainerInterface $container): WebhookHandler
    {
        /** @var ReadWebhooks $read */
        $read = $container->get(ReadWebhooks::class);
        /** @var UpdateWebhook $update */
        $update = $container->get(UpdateWebhook::class);
        /** @var DeleteWebhook $delete */
        $delete = $container->get(DeleteWebhook::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new WebhookHandler($read, $update, $delete, $responder);
    }
}
