<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\IdentityProvider\ConfiguredIdentityProviders;
use Clavia\Adapter\Secondary\IdentityProvider\GitHubIdentityProvider;
use Clavia\Adapter\Secondary\IdentityProvider\GoogleIdentityProvider;
use Clavia\Adapter\Secondary\IdentityProvider\ProviderHttp;
use Clavia\Application\Port\IdentityProviders;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

/**
 * The external providers this deployment offers: each one whose client id and secret
 * are both set, in a fixed order — Google, then GitHub.
 */
final class IdentityProvidersFactory
{
    public function __invoke(ContainerInterface $container): IdentityProviders
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $http = static function () use ($container): ProviderHttp {
            /** @var ProviderHttp */
            return $container->get(ProviderHttp::class);
        };

        $providers = [];
        if (self::isSet($settings->googleClientId) && self::isSet($settings->googleClientSecret)) {
            $providers[] = new GoogleIdentityProvider(
                $http(),
                $settings->googleClientId,
                $settings->googleClientSecret,
            );
        }
        if (self::isSet($settings->githubClientId) && self::isSet($settings->githubClientSecret)) {
            $providers[] = new GitHubIdentityProvider(
                $http(),
                $settings->githubClientId,
                $settings->githubClientSecret,
            );
        }

        return new ConfiguredIdentityProviders($providers);
    }

    /**
     * @psalm-assert-if-true non-empty-string $value
     */
    private static function isSet(?string $value): bool
    {
        return $value !== null && $value !== '';
    }
}
