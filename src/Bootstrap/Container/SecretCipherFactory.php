<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Infrastructure\Crypto\AesGcmSecretCipher;
use Psr\Container\ContainerInterface;

final class SecretCipherFactory
{
    public function __invoke(ContainerInterface $container): AesGcmSecretCipher
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);

        return new AesGcmSecretCipher($settings->secretEncryptionKey, $random);
    }
}
