<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\ClientAuthentication\ClientFailureThrottle;
use Clavia\Application\OAuth2\Dpop\ReadDpopProof;
use Clavia\Application\OAuth2\Token\AuthorizationCodeGrant;
use Clavia\Application\OAuth2\Token\ClientCredentialsGrant;
use Clavia\Application\OAuth2\Token\DeviceCodeGrant;
use Clavia\Application\OAuth2\Token\IssueToken;
use Clavia\Application\OAuth2\Token\RefreshTokenGrant;
use Clavia\Application\Oidc\Discovery\ProviderMetadata;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class IssueTokenFactory
{
    public function __invoke(ContainerInterface $container): IssueToken
    {
        /** @var ClientAuthenticator $authenticator */
        $authenticator = $container->get(ClientAuthenticator::class);
        /** @var ClientFailureThrottle $throttle */
        $throttle = $container->get(ClientFailureThrottle::class);
        /** @var AuthorizationCodeGrant $authorizationCode */
        $authorizationCode = $container->get(AuthorizationCodeGrant::class);
        /** @var ClientCredentialsGrant $clientCredentials */
        $clientCredentials = $container->get(ClientCredentialsGrant::class);
        /** @var RefreshTokenGrant $refreshToken */
        $refreshToken = $container->get(RefreshTokenGrant::class);
        /** @var DeviceCodeGrant $deviceCode */
        $deviceCode = $container->get(DeviceCodeGrant::class);

        // Every grant the token endpoint offers. A grant not listed here does not exist.
        /** @var ReadDpopProof $dpop */
        $dpop = $container->get(ReadDpopProof::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $tokenEndpoint = $settings->issuer() . ProviderMetadata::TOKEN_ENDPOINT;

        return new IssueToken(
            $authenticator,
            $throttle,
            $dpop,
            $tokenEndpoint,
            $authorizationCode,
            $clientCredentials,
            $refreshToken,
            $deviceCode
        );
    }
}
