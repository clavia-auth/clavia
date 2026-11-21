<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\Mail\NoMailer;
use Clavia\Adapter\Secondary\Mail\OutboxMailer;
use Clavia\Adapter\Secondary\Mail\SmtpMailer;
use Clavia\Application\Port\Mailer;
use Clavia\Application\Port\MailOutbox;
use Clavia\Configuration\EmailBackend;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Mime\Address;

/**
 * The mailer `CLAVIA_EMAIL_BACKEND` names. The settings already refused `console`
 * outside development and `smtp` without a server.
 */
final class MailerFactory
{
    public function __invoke(ContainerInterface $container): Mailer
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        /** @var LoggerInterface $logger */
        $logger = $container->get(LoggerInterface::class);

        return match ($settings->emailBackend) {
            EmailBackend::None => new NoMailer(),
            EmailBackend::Console => new OutboxMailer(self::outbox($container), $logger),
            EmailBackend::Smtp => self::smtp($settings, $logger),
        };
    }

    private static function outbox(ContainerInterface $container): MailOutbox
    {
        /** @var MailOutbox $outbox */
        $outbox = $container->get(MailOutbox::class);

        return $outbox;
    }

    private static function smtp(Settings $settings, LoggerInterface $logger): SmtpMailer
    {
        $host = $settings->smtpHost ?? '';
        $port = $settings->smtpPort;
        assert($host !== '' && $port > 0);

        return new SmtpMailer(
            SmtpMailer::transport(
                $host,
                $port,
                $settings->smtpStarttls,
                $settings->smtpUsername,
                $settings->smtpPassword,
                $logger,
            ),
            new Address($settings->emailSender()),
            $logger,
        );
    }
}
