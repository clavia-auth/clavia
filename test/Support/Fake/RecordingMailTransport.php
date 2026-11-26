<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Adapter\Secondary\Mail\MailTransport;
use Clavia\Application\Port\RenderedMail;

/** A mail backend that keeps what it is handed, worded. */
final class RecordingMailTransport implements MailTransport
{
    /** @var list<RenderedMail> Oldest first. */
    public array $delivered = [];

    #[\Override]
    public function canSend(): bool
    {
        return true;
    }

    #[\Override]
    public function deliver(RenderedMail $mail): void
    {
        $this->delivered[] = $mail;
    }
}
