<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Token\IssueToken;
use Clavia\Application\Oidc\Discovery\ProviderMetadata;
use Clavia\Configuration\ClientRegistration;
use Clavia\Configuration\Settings;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\ScopeSet;
use Psr\Container\ContainerInterface;

final class ProviderMetadataFactory
{
    public function __invoke(ContainerInterface $container): ProviderMetadata
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        /** @var IssueToken $issueToken */
        $issueToken = $container->get(IssueToken::class);
        /** @var SigningAlgorithm $algorithm */
        $algorithm = $container->get(SigningAlgorithm::class);

        $issuer = $settings->issuer();
        assert($issuer !== '');

        return new ProviderMetadata(
            $issuer,
            ScopeSet::fromString(implode(' ', $settings->scopesSupported)),
            $issueToken->supportedGrantTypes(),
            $issueToken->supportedAuthMethods(),
            [$algorithm],
            $settings->clientRegistration !== ClientRegistration::Off,
            $settings->languages,
        );
    }
}
