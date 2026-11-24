<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Adapter\Primary\Cli\Sqs\QueueMessage;
use Clavia\Adapter\Primary\Cli\Sqs\QueueMessages;
use Clavia\Adapter\Primary\Cli\Sqs\QueueMessagesFactory;

/**
 * A queue that hands out the messages it was given, in order, and records which were deleted. A
 * message not deleted stays out, as it would until its visibility timeout.
 */
final class FakeQueueMessages implements QueueMessages, QueueMessagesFactory
{
    /** @var list<QueueMessage> */
    private array $waiting;

    /** @var list<string> Ids of the deleted messages. */
    public array $deleted = [];

    /** @var list<string> The URLs the command opened. */
    public array $opened = [];

    public function __construct(QueueMessage ...$messages)
    {
        $this->waiting = array_values($messages);
    }

    /** @param non-empty-string $id */
    public static function message(string $id, string $body, ?string $connection = null): QueueMessage
    {
        return new QueueMessage($id, 'receipt-' . $id, $body, $connection);
    }

    #[\Override]
    public function open(string $queueUrl): QueueMessages
    {
        $this->opened[] = $queueUrl;

        return $this;
    }

    #[\Override]
    public function receive(int $max, int $waitSeconds): array
    {
        $handed = array_slice($this->waiting, 0, $max);
        $this->waiting = array_slice($this->waiting, $max);

        return $handed;
    }

    #[\Override]
    public function delete(QueueMessage $message): void
    {
        $this->deleted[] = $message->id;
    }
}
