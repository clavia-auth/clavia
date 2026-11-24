<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli\Sqs;

use Aws\Sqs\SqsClient;

/**
 * An SQS queue, through the AWS SDK: `ReceiveMessage` with long polling and the `connection`
 * attribute, `DeleteMessage` by receipt.
 */
final readonly class SqsQueueMessages implements QueueMessages
{
    public function __construct(
        private SqsClient $client,
        private string $queueUrl,
    ) {
    }

    #[\Override]
    public function receive(int $max, int $waitSeconds): array
    {
        $result = $this->client->receiveMessage([
            'QueueUrl' => $this->queueUrl,
            'MaxNumberOfMessages' => $max,
            'WaitTimeSeconds' => $waitSeconds,
            'MessageAttributeNames' => ['connection'],
        ]);
        /** @var mixed $messages */
        $messages = $result->get('Messages');
        if (! is_array($messages)) {
            return [];
        }

        $received = [];
        /** @var mixed $message */
        foreach ($messages as $message) {
            if (! is_array($message)) {
                continue;
            }
            /** @var mixed $id */
            $id = $message['MessageId'] ?? null;
            /** @var mixed $receipt */
            $receipt = $message['ReceiptHandle'] ?? null;
            /** @var mixed $body */
            $body = $message['Body'] ?? null;
            if (! is_string($id) || $id === '' || ! is_string($receipt) || $receipt === '' || ! is_string($body)) {
                continue;
            }
            $received[] = new QueueMessage($id, $receipt, $body, self::connection($message));
        }

        return $received;
    }

    /**
     * The `connection` message attribute, when it is a string one.
     *
     * @param array<array-key, mixed> $message
     */
    private static function connection(array $message): ?string
    {
        /** @var mixed $attributes */
        $attributes = $message['MessageAttributes'] ?? null;
        /** @var mixed $attribute */
        $attribute = is_array($attributes) ? ($attributes['connection'] ?? null) : null;
        /** @var mixed $value */
        $value = is_array($attribute) ? ($attribute['StringValue'] ?? null) : null;

        return is_string($value) ? $value : null;
    }

    #[\Override]
    public function delete(QueueMessage $message): void
    {
        $this->client->deleteMessage(['QueueUrl' => $this->queueUrl, 'ReceiptHandle' => $message->receiptHandle]);
    }
}
