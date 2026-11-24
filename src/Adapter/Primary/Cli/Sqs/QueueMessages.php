<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli\Sqs;

/**
 * The queue a listener reads accounts from: receive by long polling, delete what is done with. A
 * message not deleted comes back after its visibility timeout, and the queue's redrive policy sends
 * it to a dead-letter queue after enough tries. Kept small so the listener is tested with a double.
 */
interface QueueMessages
{
    /**
     * @param int<1, 10> $max         SQS hands out at most ten at a time.
     * @param int<0, 20> $waitSeconds Long polling: how long to wait for a first message.
     *
     * @return list<QueueMessage>
     */
    public function receive(int $max, int $waitSeconds): array;

    public function delete(QueueMessage $message): void;
}
