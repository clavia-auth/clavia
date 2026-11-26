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
 * What a mail says, without its words: which mail, and the values it carries (the site's name, a link,
 * a code), each an argument of its message. A lifetime is a number of seconds the mailer words in the
 * mail's language ("2 minutes", "24 heures"), never a phrase built here.
 */
final readonly class MailContent
{
    /**
     * @param array<non-empty-string, string> $values          The mail's arguments, by name.
     * @param positive-int|null               $lifetimeSeconds How long what it carries works, when it expires.
     */
    public function __construct(
        public MailKind $kind,
        #[\SensitiveParameter] public array $values,
        public ?int $lifetimeSeconds = null,
    ) {
    }
}
