<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Oidc\Logout\EndSession;
use Clavia\Application\Port\SignatureVerifier;
use Clavia\Application\Port\TokenSigner;
use Clavia\Configuration\Settings;
use Clavia\Domain\Client\ClientRepository;
use Psr\Container\ContainerInterface;

final class EndSessionFactory
{
    public function __invoke(ContainerInterface $container): EndSession
    {
        /** @var Sessions $sessions */
        $sessions = $container->get(Sessions::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var TokenSigner $keys */
        $keys = $container->get(TokenSigner::class);
        /** @var SignatureVerifier $verifier */
        $verifier = $container->get(SignatureVerifier::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new EndSession($sessions, $clients, $keys, $verifier, $settings->issuer());
    }
}
