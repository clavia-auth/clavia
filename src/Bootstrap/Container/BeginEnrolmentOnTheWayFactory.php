<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Mfa\BeginEnrolmentOnTheWay;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Configuration\Settings;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class BeginEnrolmentOnTheWayFactory
{
    public function __invoke(ContainerInterface $container): BeginEnrolmentOnTheWay
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var MfaFactorRepository $factors */
        $factors = $container->get(MfaFactorRepository::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        /** @var PasskeyRepository|null $passkeys */
        $passkeys = $settings->passkeysEnabled ? $container->get(PasskeyRepository::class) : null;
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);

        return new BeginEnrolmentOnTheWay($users, $factors, $passkeys, $loginStates, $secrets);
    }
}
