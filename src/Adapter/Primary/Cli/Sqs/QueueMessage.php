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
 * One message received from a queue: its id (for the log), the receipt that deletes it, its body,
 * and the `connection` attribute naming the pool, when it has one.
 */
final readonly class QueueMessage
{
    /**
     * @param non-empty-string $id
     * @param non-empty-string $receiptHandle
     */
    public function __construct(
        public string $id,
        public string $receiptHandle,
        #[\SensitiveParameter] public string $body,
        public ?string $connection,
    ) {
    }
}
