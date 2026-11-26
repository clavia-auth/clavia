<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\Mailer;
use Clavia\Application\Port\MailUnavailable;
use Clavia\Application\Port\OutgoingMail;
use Clavia\Application\Port\RenderedMail;
use ClaviaTest\Support\TestMail;

/**
 * A mailer that keeps what it is given — or, told to, refuses it as an unreachable SMTP
 * server would.
 */
final class RecordingMailer implements Mailer
{
    /** @var list<OutgoingMail> Oldest first. */
    public private(set) array $sent = [];

    public function __construct(
        private readonly bool $canSend = true,
        public bool $failing = false,
    ) {
    }

    #[\Override]
    public function canSend(): bool
    {
        return $this->canSend;
    }

    #[\Override]
    public function send(OutgoingMail $mail): void
    {
        if (! $this->canSend || $this->failing) {
            throw new MailUnavailable('The recording mailer was told to refuse.');
        }
        $this->sent[] = $mail;
    }

    public function last(): ?OutgoingMail
    {
        return $this->sent === [] ? null : $this->sent[array_key_last($this->sent)];
    }

    /** The last mail as the shipped catalogues word it, or null when nothing was sent. */
    public function lastRendered(): ?RenderedMail
    {
        $last = $this->last();

        return $last === null ? null : TestMail::render($last);
    }
}
