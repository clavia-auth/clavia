<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Shared\Language;

/**
 * One mail to one recipient: what it says ({@see MailContent}) and in which language, never its
 * words, which the {@see Mailer} takes from the catalogue (docs/design/translated-sign-in-pages.md
 * §4). The sender is the deployment's (`CLAVIA_EMAIL_FROM`), set by the mailer, never by the caller.
 */
final readonly class OutgoingMail
{
    /**
     * @param non-empty-string $to
     */
    public function __construct(
        public string $to,
        public MailContent $content,
        public Language $language,
    ) {
    }
}
