<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authorization\Evaluation\SubjectFacts;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\RoleRepository;
use Psr\Container\ContainerInterface;

final class SubjectFactsFactory
{
    public function __invoke(ContainerInterface $container): SubjectFacts
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var RoleRepository $roles */
        $roles = $container->get(RoleRepository::class);
        /** @var MfaFactorRepository $factors */
        $factors = $container->get(MfaFactorRepository::class);
        /** @var PasskeyRepository $passkeys */
        $passkeys = $container->get(PasskeyRepository::class);

        return new SubjectFacts(
            $users,
            $clients,
            $roles,
            $factors,
            $passkeys,
        );
    }
}
