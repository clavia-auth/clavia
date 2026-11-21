<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Passwordless\AnswerPasswordlessCode;
use Clavia\Application\Authentication\Passwordless\DescribePasswordlessChallenge;
use Clavia\Application\Authentication\Passwordless\FinishPasswordlessSignIn;
use Clavia\Application\Port\PasswordlessChallengeStore;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class AnswerPasswordlessCodeFactory
{
    public function __invoke(ContainerInterface $container): AnswerPasswordlessCode
    {
        /** @var PasswordlessChallengeStore $challenges */
        $challenges = $container->get(PasswordlessChallengeStore::class);
        /** @var DescribePasswordlessChallenge $describe */
        $describe = $container->get(DescribePasswordlessChallenge::class);
        /** @var FinishPasswordlessSignIn $finish */
        $finish = $container->get(FinishPasswordlessSignIn::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $maxAttempts = $settings->passwordlessMaxAttempts;
        assert($maxAttempts > 0);

        return new AnswerPasswordlessCode($challenges, $describe, $finish, $maxAttempts);
    }
}
