<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Configuration\InvalidSettings;
use Clavia\Configuration\Settings;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Psr\Container\ContainerInterface;

final class SigningAlgorithmFactory
{
    public function __invoke(ContainerInterface $container): SigningAlgorithm
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        // Refused when the server starts to need it rather than at the first token: the
        // configuration names an algorithm no key here can produce.
        return SigningAlgorithm::tryFrom($settings->signingAlgorithm) ?? throw new InvalidSettings(sprintf(
            "CLAVIA_SIGNING_ALGORITHM='%s' is not supported; supported: %s.",
            $settings->signingAlgorithm,
            implode(', ', array_map(static fn (SigningAlgorithm $a): string => $a->value, SigningAlgorithm::cases())),
        ));
    }
}
