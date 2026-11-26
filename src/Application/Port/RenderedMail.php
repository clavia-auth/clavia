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
 * One plain-text message to one recipient, worded in its language: what a mail transport delivers,
 * and what the development outbox ({@see MailOutbox}) shows.
 */
final readonly class RenderedMail
{
    /**
     * @param non-empty-string $to
     * @param string           $subject One line.
     */
    public function __construct(
        public string $to,
        public string $subject,
        #[\SensitiveParameter] public string $text,
    ) {
    }
}
