<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Auth\DevicePages;
use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\Device\RequestDeviceAuthorization;
use Clavia\Application\OAuth2\ReadRequestedAccess;
use Clavia\Application\Port\DeviceAuthorizationStore;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class RequestDeviceAuthorizationFactory
{
    public function __invoke(ContainerInterface $container): RequestDeviceAuthorization
    {
        /** @var ClientAuthenticator $authenticator */
        $authenticator = $container->get(ClientAuthenticator::class);
        /** @var ReadRequestedAccess $requestedAccess */
        $requestedAccess = $container->get(ReadRequestedAccess::class);
        /** @var DeviceAuthorizationStore $store */
        $store = $container->get(DeviceAuthorizationStore::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $lifetime = $settings->deviceCodeLifetime;
        assert($lifetime > 0);
        $interval = $settings->devicePollInterval;
        assert($interval > 0);

        return new RequestDeviceAuthorization(
            $authenticator,
            $requestedAccess,
            $store,
            $secrets,
            $random,
            $clock,
            $settings->issuer() . DevicePages::PATH,
            $lifetime,
            $interval,
        );
    }
}
