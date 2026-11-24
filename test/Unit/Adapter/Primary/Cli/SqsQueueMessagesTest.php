<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Cli;

use Aws\CommandInterface;
use Aws\MockHandler;
use Aws\Result;
use Aws\Sqs\SqsClient;
use Clavia\Adapter\Primary\Cli\Sqs\QueueMessage;
use Clavia\Adapter\Primary\Cli\Sqs\SqsQueueMessages;
use Clavia\Adapter\Primary\Cli\Sqs\SqsQueueMessagesFactory;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The SQS adapter against the AWS SDK's own mock handler: the requests it makes and how it reads the
 * answers, with no network.
 */
final class SqsQueueMessagesTest extends TestCase
{
    private const string QUEUE = 'https://sqs.eu-west-1.amazonaws.com/123456789012/clavia-imports';

    public function testItLongPollsAndReadsTheConnectionAttribute(): void
    {
        // The SDK's append() takes its results as func_get_args(); the constructor names them.
        $mock = new MockHandler([new Result(['Messages' => [
            // With the checksums SQS sends, which the SDK verifies: the body's MD5, and the attributes'
            // (computed by the SDK's own algorithm for this one attribute).
            [
                'MessageId' => 'm-1',
                'ReceiptHandle' => 'r-1',
                'Body' => '{"email":"grace@example.com"}',
                'MD5OfBody' => self::md5OfBody('{"email":"grace@example.com"}'),
                'MessageAttributes' => ['connection' => ['DataType' => 'String', 'StringValue' => 'staff']],
                'MD5OfMessageAttributes' => '45a867d0e021c5b3d4c2fa622bae672e',
            ],
            [
                'MessageId' => 'm-2',
                'ReceiptHandle' => 'r-2',
                'Body' => '{"email":"alan@example.com"}',
                'MD5OfBody' => self::md5OfBody('{"email":"alan@example.com"}'),
            ],
            // Without an id: left out.
            ['MessageId' => '', 'ReceiptHandle' => 'r-3', 'Body' => 'x', 'MD5OfBody' => self::md5OfBody('x')],
        ]])]);

        $messages = self::queue($mock)->receive(10, 20);

        self::assertEquals([
            new QueueMessage('m-1', 'r-1', '{"email":"grace@example.com"}', 'staff'),
            new QueueMessage('m-2', 'r-2', '{"email":"alan@example.com"}', null),
        ], $messages);
        $command = $mock->getLastCommand();
        self::assertInstanceOf(CommandInterface::class, $command);
        self::assertSame('ReceiveMessage', $command->getName());
        self::assertSame(self::QUEUE, $command['QueueUrl']);
        self::assertSame(20, $command['WaitTimeSeconds']);
        self::assertSame(10, $command['MaxNumberOfMessages']);
        self::assertSame(['connection'], $command['MessageAttributeNames']);
    }

    public function testAnEmptyQueueIsNoMessage(): void
    {
        $mock = new MockHandler([new Result([])]);

        self::assertSame([], self::queue($mock)->receive(1, 20));
    }

    public function testAMessageIsDeletedByItsReceipt(): void
    {
        $mock = new MockHandler([new Result([])]);

        self::queue($mock)->delete(new QueueMessage('m-1', 'r-1', '{}', null));

        $command = $mock->getLastCommand();
        self::assertSame('DeleteMessage', $command->getName());
        self::assertSame('r-1', $command['ReceiptHandle']);
    }

    /** @return iterable<string, array{string}> */
    public static function notQueues(): iterable
    {
        yield 'http' => ['http://sqs.eu-west-1.amazonaws.com/123456789012/clavia-imports'];
        yield 'another host' => ['https://sqs.eu-west-1.attacker.example/123456789012/clavia-imports'];
        yield 'no account' => ['https://sqs.eu-west-1.amazonaws.com/clavia-imports'];
        yield 'a path beyond the queue' => ['https://sqs.eu-west-1.amazonaws.com/123456789012/clavia-imports/x'];
    }

    #[DataProvider('notQueues')]
    public function testAUrlThatIsNotAnSqsQueueIsRefused(string $url): void
    {
        $this->expectException(InvalidArgumentException::class);

        new SqsQueueMessagesFactory(null)->open($url);
    }

    public function testAQueueUrlOpensWithItsOwnRegion(): void
    {
        self::assertInstanceOf(SqsQueueMessages::class, new SqsQueueMessagesFactory(null)->open(self::QUEUE));
        self::assertInstanceOf(
            SqsQueueMessages::class,
            new SqsQueueMessagesFactory(null)->open('https://sqs-fips.us-east-1.amazonaws.com/123456789012/q.fifo'),
        );
    }

    /**
     * The checksum SQS sends with a body (`MD5OfBody`), which the SDK checks: an integrity check the
     * protocol fixes, not a use of MD5 for anything secret.
     *
     * @psalm-suppress WeakHash
     */
    private static function md5OfBody(string $body): string
    {
        return md5($body);
    }

    private static function queue(MockHandler $mock): SqsQueueMessages
    {
        return new SqsQueueMessages(new SqsClient([
            'version' => '2012-11-05',
            'region' => 'eu-west-1',
            'credentials' => ['key' => 'test', 'secret' => 'test'],
            'handler' => $mock,
        ]), self::QUEUE);
    }
}
