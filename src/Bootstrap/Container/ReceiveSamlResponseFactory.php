<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\External\Saml\ReceiveSamlResponse;
use Clavia\Application\Port\Saml\SamlResponseStore;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class ReceiveSamlResponseFactory
{
    public function __invoke(ContainerInterface $container): ReceiveSamlResponse
    {
        /** @var SamlResponseStore $responses */
        $responses = $container->get(SamlResponseStore::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);

        return new ReceiveSamlResponse($responses, $secrets);
    }
}
