<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\EmailSendLimit;
use Clavia\Application\Authentication\Passwordless\DescribePasswordlessChallenge;
use Clavia\Application\Authentication\Passwordless\SignInMail;
use Clavia\Application\Authentication\Passwordless\StartPasswordlessSignIn;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\AttemptCounter;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\Mailer;
use Clavia\Application\Port\PasswordlessChallengeStore;
use Clavia\Configuration\Settings;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class StartPasswordlessSignInFactory
{
    public function __invoke(ContainerInterface $container): StartPasswordlessSignIn
    {
        /** @var ConnectionAccess $access */
        $access = $container->get(ConnectionAccess::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var PasswordlessChallengeStore $challenges */
        $challenges = $container->get(PasswordlessChallengeStore::class);
        /** @var AttemptCounter $counter */
        $counter = $container->get(AttemptCounter::class);
        /** @var Mailer $mailer */
        $mailer = $container->get(Mailer::class);
        /** @var SignInMail $mail */
        $mail = $container->get(SignInMail::class);
        /** @var DescribePasswordlessChallenge $describe */
        $describe = $container->get(DescribePasswordlessChallenge::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $codeLifetime = $settings->passwordlessCodeLifetime;
        $linkLifetime = $settings->passwordlessLinkLifetime;
        $sendLimit = $settings->passwordlessSendLimit;
        assert($codeLifetime > 0 && $linkLifetime > 0 && $sendLimit > 0);

        return new StartPasswordlessSignIn(
            $access,
            $clients,
            $loginStates,
            $challenges,
            new EmailSendLimit($counter, $sendLimit, 'passwordless'),
            $mailer,
            $mail,
            $describe,
            $secrets,
            $random,
            $codeLifetime,
            $linkLifetime,
        );
    }
}
