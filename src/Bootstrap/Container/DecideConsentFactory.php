<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Consent\DecideConsent;
use Clavia\Application\OAuth2\Consent\HeldConsents;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class DecideConsentFactory
{
    public function __invoke(ContainerInterface $container): DecideConsent
    {
        /** @var HeldConsents $held */
        $held = $container->get(HeldConsents::class);
        /** @var ConsentRepository $consents */
        $consents = $container->get(ConsentRepository::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new DecideConsent($held, $consents, $clock);
    }
}
