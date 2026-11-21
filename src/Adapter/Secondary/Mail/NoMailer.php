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
use Clavia\Application\Port\MailUnavailable;
use Clavia\Application\Port\OutgoingMail;

/**
 * `CLAVIA_EMAIL_BACKEND=none`: this deployment sends no mail. Every connection that
 * depends on mail is then unusable — not offered, not accepted — instead of failing
 * when someone asks for a code.
 */
final readonly class NoMailer implements Mailer
{
    #[\Override]
    public function canSend(): bool
    {
        return false;
    }

    #[\Override]
    public function send(OutgoingMail $mail): void
    {
        throw new MailUnavailable('This deployment sends no mail (CLAVIA_EMAIL_BACKEND=none).');
    }
}
