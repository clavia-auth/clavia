<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Passkey\UsePasskey;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\PasskeyVerifier;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class UsePasskeyFactory
{
    public function __invoke(ContainerInterface $container): UsePasskey
    {
        /** @var PasskeyRepository $passkeys */
        $passkeys = $container->get(PasskeyRepository::class);
        /** @var PasskeyVerifier $verifier */
        $verifier = $container->get(PasskeyVerifier::class);
        /** @var RelyingParty $relyingParty */
        $relyingParty = $container->get(RelyingParty::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new UsePasskey($passkeys, $verifier, $relyingParty, $clock, $events);
    }
}
