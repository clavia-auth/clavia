<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Users\WithdrawConsent;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class WithdrawConsentFactory
{
    public function __invoke(ContainerInterface $container): WithdrawConsent
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var ConsentRepository $consents */
        $consents = $container->get(ConsentRepository::class);

        return new WithdrawConsent($users, $consents);
    }
}
