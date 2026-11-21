<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Oidc\CompactJws;
use Clavia\Application\Oidc\Logout\BackChannelLogout;
use Clavia\Application\Port\BackChannelLogoutDelivery;
use Clavia\Application\Port\DeferredTasks;
use Clavia\Application\Port\TokenSigner;
use Clavia\Configuration\Settings;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class BackChannelLogoutFactory
{
    public function __invoke(ContainerInterface $container): BackChannelLogout
    {
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var TokenSigner $signer */
        $signer = $container->get(TokenSigner::class);
        /** @var CompactJws $jws */
        $jws = $container->get(CompactJws::class);
        /** @var BackChannelLogoutDelivery $delivery */
        $delivery = $container->get(BackChannelLogoutDelivery::class);
        /** @var DeferredTasks $deferred */
        $deferred = $container->get(DeferredTasks::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $issuer = $settings->issuer();
        $lifetime = $settings->backchannelLogoutTokenLifetime;
        assert($issuer !== '' && $lifetime > 0);

        return new BackChannelLogout(
            $clients,
            $signer,
            $jws,
            $delivery,
            $deferred,
            $secrets,
            $clock,
            $issuer,
            $lifetime,
        );
    }
}
