<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\MailOutbox;
use Clavia\Application\Port\RenderedMail;

/**
 * The development outbox kept in an array.
 */
final class InMemoryMailOutbox implements MailOutbox
{
    /** @var list<RenderedMail> Newest first. */
    private array $mails = [];

    #[\Override]
    public function record(RenderedMail $mail): void
    {
        array_unshift($this->mails, $mail);
    }

    #[\Override]
    public function recent(int $limit): array
    {
        return array_slice($this->mails, 0, $limit);
    }
}
