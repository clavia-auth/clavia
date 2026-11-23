<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Dpop\ReadDpopProof;
use Clavia\Application\OAuth2\ProtectedResource\CheckSenderConstraint;
use Psr\Container\ContainerInterface;

final class CheckSenderConstraintFactory
{
    public function __invoke(ContainerInterface $container): CheckSenderConstraint
    {
        /** @var ReadDpopProof $dpop */
        $dpop = $container->get(ReadDpopProof::class);

        return new CheckSenderConstraint($dpop);
    }
}
