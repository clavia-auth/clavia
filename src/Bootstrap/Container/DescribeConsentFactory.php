<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Consent\DescribeConsent;
use Clavia\Application\OAuth2\Consent\HeldConsents;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\ScopeSet;
use Psr\Container\ContainerInterface;

final class DescribeConsentFactory
{
    public function __invoke(ContainerInterface $container): DescribeConsent
    {
        /** @var HeldConsents $held */
        $held = $container->get(HeldConsents::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new DescribeConsent($held, ScopeSet::fromString(implode(' ', $settings->scopesSupported)));
    }
}
