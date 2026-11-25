<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Webhooks\WebhookSecrets;
use Clavia\Application\Port\SecretCipher;
use Clavia\Domain\Shared\RandomSource;
use Psr\Container\ContainerInterface;

final class WebhookSecretsFactory
{
    public function __invoke(ContainerInterface $container): WebhookSecrets
    {
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var SecretCipher $cipher */
        $cipher = $container->get(SecretCipher::class);

        return new WebhookSecrets($random, $cipher);
    }
}
