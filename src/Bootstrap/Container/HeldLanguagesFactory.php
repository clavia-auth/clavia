<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\HeldLanguages;
use Clavia\Application\Port\ConsentStateStore;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\MfaChallengeStore;
use Psr\Container\ContainerInterface;

final class HeldLanguagesFactory
{
    public function __invoke(ContainerInterface $container): HeldLanguages
    {
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var ConsentStateStore $consentStates */
        $consentStates = $container->get(ConsentStateStore::class);
        /** @var MfaChallengeStore $challenges */
        $challenges = $container->get(MfaChallengeStore::class);

        return new HeldLanguages($loginStates, $consentStates, $challenges);
    }
}
