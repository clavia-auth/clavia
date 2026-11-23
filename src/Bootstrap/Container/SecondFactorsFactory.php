<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Mfa\SecondFactors;
use Clavia\Configuration\Settings;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Psr\Container\ContainerInterface;

final class SecondFactorsFactory
{
    public function __invoke(ContainerInterface $container): SecondFactors
    {
        /** @var MfaFactorRepository $factors */
        $factors = $container->get(MfaFactorRepository::class);
        /** @var RecoveryCodeRepository $recoveryCodes */
        $recoveryCodes = $container->get(RecoveryCodeRepository::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        /** @var PasskeyRepository|null $passkeys */
        $passkeys = $settings->passkeysEnabled ? $container->get(PasskeyRepository::class) : null;

        return new SecondFactors($factors, $recoveryCodes, $passkeys);
    }
}
