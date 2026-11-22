<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Account\AccountMail;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class AccountMailFactory
{
    public function __invoke(ContainerInterface $container): AccountMail
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $site = $settings->rootDomain;
        $issuer = $settings->issuer();
        $verification = $settings->verificationLinkLifetime;
        $reset = $settings->resetLinkLifetime;
        assert($site !== '' && $issuer !== '' && $verification > 0 && $reset > 0);

        return new AccountMail(
            $site,
            $issuer,
            $verification,
            $reset,
        );
    }
}
