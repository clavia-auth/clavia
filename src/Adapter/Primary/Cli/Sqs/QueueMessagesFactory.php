<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli\Sqs;

use InvalidArgumentException;

/** Opens the queue an operator names on the command line. */
interface QueueMessagesFactory
{
    /**
     * @throws InvalidArgumentException When the URL is not an SQS queue's, or the SDK is missing.
     */
    public function open(string $queueUrl): QueueMessages;
}
