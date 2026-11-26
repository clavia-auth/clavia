<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Mail;

use Clavia\Application\Port\MailUnavailable;
use Clavia\Application\Port\RenderedMail;

/**
 * How a worded mail leaves this server: the backend `CLAVIA_EMAIL_BACKEND` names (`smtp`, `console`,
 * `none`). The mail adapter's own interface, behind {@see RenderedMailer}, which words each mail before
 * handing it here (docs/design/translated-sign-in-pages.md §4).
 */
interface MailTransport
{
    /**
     * Whether this deployment sends mail at all. False means every way of signing in that
     * depends on mail is unusable, rather than failing at the moment someone tries.
     */
    public function canSend(): bool;

    /**
     * @throws MailUnavailable
     */
    public function deliver(RenderedMail $mail): void;
}
