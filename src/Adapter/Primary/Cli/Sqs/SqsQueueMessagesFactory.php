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
use InvalidArgumentException;

/**
 * Builds the SQS client for a queue URL. `aws/aws-sdk-php` is a Composer suggestion, as for the
 * `aws-kms` signing backend: without it, the command says what to install. Credentials come from the
 * SDK's default chain (an IAM role, the environment); the region from `CLAVIA_AWS_REGION`, or else the
 * queue URL's own (`https://sqs.<region>.amazonaws.com/<account>/<queue>`).
 */
final readonly class SqsQueueMessagesFactory implements QueueMessagesFactory
{
    /** `https://sqs[-fips].<region>.amazonaws.com[.cn]/<account id>/<queue name>[.fifo]`. */
    private const string URL = '#^https://sqs(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?'
        . '/[0-9]{12}/[A-Za-z0-9_-]{1,80}(?:\.fifo)?$#D';

    /** @param string|null $region CLAVIA_AWS_REGION. */
    public function __construct(private ?string $region)
    {
    }

    #[\Override]
    public function open(string $queueUrl): QueueMessages
    {
        if (! class_exists(SqsClient::class)) {
            throw new InvalidArgumentException(
                'Reading an SQS queue needs aws/aws-sdk-php: composer require aws/aws-sdk-php',
            );
        }
        if (preg_match(self::URL, $queueUrl, $match) !== 1) {
            throw new InvalidArgumentException(
                'Not an SQS queue URL: https://sqs.<region>.amazonaws.com/<account id>/<queue name>.',
            );
        }

        return new SqsQueueMessages(
            new SqsClient(['version' => '2012-11-05', 'region' => $this->region ?? $match[1]]),
            $queueUrl,
        );
    }
}
