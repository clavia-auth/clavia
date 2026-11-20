<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Mfa\ResumeTotpEnrollment;
use Clavia\Application\Authentication\Mfa\TotpSeeds;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class ResumeTotpEnrollmentFactory
{
    public function __invoke(ContainerInterface $container): ResumeTotpEnrollment
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var MfaFactorRepository $factors */
        $factors = $container->get(MfaFactorRepository::class);
        /** @var TotpSeeds $seeds */
        $seeds = $container->get(TotpSeeds::class);

        return new ResumeTotpEnrollment($users, $factors, $seeds);
    }
}
