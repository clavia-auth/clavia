<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Metrics;

use Clavia\Application\Port\Mailer;
use Clavia\Application\Port\MailUnavailable;
use Clavia\Application\Port\Metrics;
use Clavia\Application\Port\OutgoingMail;

/**
 * The mailer, counting what it hands over (#23): `sent`, or `failed` when the mail server would not
 * take it, which every caller then answers as mail being unavailable. Nothing of the message itself.
 */
final readonly class CountingMailer implements Mailer
{
    /** @param Mailer $mailer The backend `CLAVIA_EMAIL_BACKEND` names: what actually sends. */
    public function __construct(
        public Mailer $mailer,
        private Metrics $metrics,
    ) {
    }

    #[\Override]
    public function canSend(): bool
    {
        return $this->mailer->canSend();
    }

    #[\Override]
    public function send(OutgoingMail $mail): void
    {
        try {
            $this->mailer->send($mail);
        } catch (MailUnavailable $failure) {
            $this->metrics->count(Metric::Mail, ['outcome' => 'failed']);

            throw $failure;
        }
        $this->metrics->count(Metric::Mail, ['outcome' => 'sent']);
    }
}
