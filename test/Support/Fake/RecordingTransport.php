<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace ClaviaTest\Support\Fake;

use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mailer\SentMessage;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\RawMessage;

/**
 * A Symfony Mailer transport that keeps what it is given — or refuses it as an SMTP
 * server that cannot be reached would.
 */
final class RecordingTransport implements TransportInterface
{
    /** @var list<RawMessage> */
    public private(set) array $sent = [];

    public function __construct(private readonly bool $failing = false)
    {
    }

    #[\Override]
    public function send(RawMessage $message, ?Envelope $envelope = null): ?SentMessage
    {
        if ($this->failing) {
            throw new TransportException('Connection to "smtp.acme.com:587" refused.');
        }
        $this->sent[] = $message;

        return null;
    }

    #[\Override]
    public function __toString(): string
    {
        return 'recording://';
    }
}
