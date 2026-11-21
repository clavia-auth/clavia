<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

/**
 * Where email leaves this server.
 *
 * Synchronous: `send` returns once the message is accepted for delivery — by the SMTP
 * server, or by the development outbox — so the caller knows whether to say "check your
 * email" or "try again later".
 */
interface Mailer
{
    /**
     * Whether this deployment sends mail at all. False means every way of signing in that
     * depends on mail is unusable, rather than failing at the moment someone tries.
     */
    public function canSend(): bool;

    /**
     * @throws MailUnavailable
     */
    public function send(OutgoingMail $mail): void;
}
