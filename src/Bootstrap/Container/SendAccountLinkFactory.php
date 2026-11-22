<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Account\AccountMail;
use Clavia\Application\Authentication\Account\SendAccountLink;
use Clavia\Application\Authentication\EmailSendLimit;
use Clavia\Application\Port\AccountLinkStore;
use Clavia\Application\Port\AttemptCounter;
use Clavia\Application\Port\Mailer;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class SendAccountLinkFactory
{
    public function __invoke(ContainerInterface $container): SendAccountLink
    {
        /** @var AccountLinkStore $links */
        $links = $container->get(AccountLinkStore::class);
        /** @var AttemptCounter $counter */
        $counter = $container->get(AttemptCounter::class);
        /** @var Mailer $mailer */
        $mailer = $container->get(Mailer::class);
        /** @var AccountMail $mail */
        $mail = $container->get(AccountMail::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $limit = $settings->accountEmailSendLimit;
        $verification = $settings->verificationLinkLifetime;
        $reset = $settings->resetLinkLifetime;
        assert($limit > 0 && $verification > 0 && $reset > 0);

        return new SendAccountLink(
            $links,
            new EmailSendLimit($counter, $limit, 'account'),
            $mailer,
            $mail,
            $secrets,
            $verification,
            $reset,
        );
    }
}
