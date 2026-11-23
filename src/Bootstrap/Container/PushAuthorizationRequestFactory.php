<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Authorize\AuthorizationRequestRules;
use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\Dpop\ReadDpopProof;
use Clavia\Application\OAuth2\Par\PushAuthorizationRequest;
use Clavia\Application\Oidc\Discovery\ProviderMetadata;
use Clavia\Application\Port\PushedAuthorizationRequestStore;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class PushAuthorizationRequestFactory
{
    public function __invoke(ContainerInterface $container): PushAuthorizationRequest
    {
        /** @var ClientAuthenticator $authenticator */
        $authenticator = $container->get(ClientAuthenticator::class);
        /** @var AuthorizationRequestRules $rules */
        $rules = $container->get(AuthorizationRequestRules::class);
        /** @var PushedAuthorizationRequestStore $pushedRequests */
        $pushedRequests = $container->get(PushedAuthorizationRequestStore::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $lifetime = $settings->parLifetime;
        assert($lifetime > 0);

        /** @var ReadDpopProof $dpop */
        $dpop = $container->get(ReadDpopProof::class);
        $endpoint = $settings->issuer() . ProviderMetadata::PUSHED_AUTHORIZATION_REQUEST_ENDPOINT;

        return new PushAuthorizationRequest(
            $authenticator,
            $rules,
            $pushedRequests,
            $secrets,
            $lifetime,
            $dpop,
            $endpoint,
        );
    }
}
