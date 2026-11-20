<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Mfa\TotpSeeds;
use Clavia\Application\Port\SecretCipher;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class TotpSeedsFactory
{
    public function __invoke(ContainerInterface $container): TotpSeeds
    {
        /** @var SecretCipher $cipher */
        $cipher = $container->get(SecretCipher::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new TotpSeeds($cipher, sprintf('Clavia (%s)', $settings->rootDomain));
    }
}
