<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Mail;

use Clavia\Application\Port\Mailer;
use Clavia\Application\Port\MailOutbox;
use Clavia\Application\Port\OutgoingMail;
use Psr\Log\LoggerInterface;

/**
 * `CLAVIA_EMAIL_BACKEND=console`, for development: nothing leaves the machine. Each
 * message is written to the log whole — sign-in codes and links included, which is why
 * the settings refuse this backend anywhere but development — and kept in the outbox,
 * where `bin/clavia mail:outbox` and the test suite read it.
 */
final readonly class OutboxMailer implements Mailer
{
    public function __construct(
        private MailOutbox $outbox,
        private LoggerInterface $logger,
    ) {
    }

    #[\Override]
    public function canSend(): bool
    {
        return true;
    }

    #[\Override]
    public function send(OutgoingMail $mail): void
    {
        $this->outbox->record($mail);
        $this->logger->info("Mail (console backend) to {to}: {subject}\n{text}", [
            'to' => $mail->to,
            'subject' => $mail->subject,
            'text' => $mail->text,
        ]);
    }
}
