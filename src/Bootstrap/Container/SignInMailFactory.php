<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Passwordless\SignInMail;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class SignInMailFactory
{
    public function __invoke(ContainerInterface $container): SignInMail
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $site = $settings->rootDomain;
        $issuer = $settings->issuer();
        $codeLifetime = $settings->passwordlessCodeLifetime;
        $linkLifetime = $settings->passwordlessLinkLifetime;
        assert($site !== '' && $issuer !== '' && $codeLifetime > 0 && $linkLifetime > 0);

        return new SignInMail($site, $issuer, $codeLifetime, $linkLifetime);
    }
}
