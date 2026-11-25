<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Http;

use Clavia\Adapter\Secondary\Http\HttpWebhookSender;
use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Domain\Shared\Url;
use Clavia\Domain\Webhook\DeliveryFailure;
use ClaviaTest\Support\Fake\FakeHttpClient;
use Fig\Http\Message\StatusCodeInterface;
use GuzzleHttp\Exception\ConnectException;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\Response\EmptyResponse;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/** The webhook sender over PSR-18 (docs/design/webhooks.md §2), against a client with nothing on the wire. */
final class HttpWebhookSenderTest extends TestCase
{
    public function testItPostsTheBodyAndHeadersAndReadsTheStatusOnly(): void
    {
        $http = new FakeHttpClient(
            static fn (): ResponseInterface => new EmptyResponse(StatusCodeInterface::STATUS_NO_CONTENT),
        );

        $outcome = self::sender($http)->send(
            Url::fromString('https://hooks.example/audit'),
            ['webhook-id' => 'event-1', 'content-type' => 'application/json'],
            '{"type":"user.created"}',
        );

        self::assertNull($outcome->failure);
        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $outcome->statusCode);
        $request = $http->requests[0];
        self::assertSame('POST', $request->getMethod());
        self::assertSame('event-1', $request->getHeaderLine('webhook-id'));
        self::assertSame('Clavia', $request->getHeaderLine('User-Agent'));
        self::assertSame('{"type":"user.created"}', (string) $request->getBody());
    }

    public function testAnythingButA2xxIsAFailureRedirectsIncluded(): void
    {
        $statuses = [
            StatusCodeInterface::STATUS_FOUND,
            StatusCodeInterface::STATUS_BAD_REQUEST,
            StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE,
        ];
        foreach ($statuses as $status) {
            $http = new FakeHttpClient(static fn (): ResponseInterface => new EmptyResponse($status));

            $outcome = self::sender($http)->send(Url::fromString('https://hooks.example/audit'), [], '{}');

            self::assertSame(DeliveryFailure::Status, $outcome->failure, (string) $status);
            self::assertSame($status, $outcome->statusCode);
        }
    }

    public function testAReceiverThatCannotBeReachedIsAConnectionFailure(): void
    {
        $http = new FakeHttpClient(static fn (RequestInterface $request): never
            => throw new ConnectException('Connection refused', $request));

        $outcome = self::sender($http)->send(Url::fromString('https://hooks.example/audit'), [], '{}');

        self::assertSame(DeliveryFailure::Connection, $outcome->failure);
        self::assertNull($outcome->statusCode);
    }

    public function testAUrlThePolicyRefusesNowIsNeverSentTo(): void
    {
        $http = new FakeHttpClient(
            static fn (): ResponseInterface => new EmptyResponse(StatusCodeInterface::STATUS_OK),
        );
        $sender = new HttpWebhookSender(
            $http,
            new RequestFactory(),
            new StreamFactory(),
            new OutboundUrlPolicy(false, static fn (): array => ['169.254.169.254']),
        );

        $outcome = $sender->send(Url::fromString('https://hooks.example/audit'), [], '{}');

        self::assertSame(DeliveryFailure::RefusedUrl, $outcome->failure);
        self::assertSame([], $http->requests);
    }

    private static function sender(FakeHttpClient $http): HttpWebhookSender
    {
        return new HttpWebhookSender(
            $http,
            new RequestFactory(),
            new StreamFactory(),
            new OutboundUrlPolicy(false, static fn (): array => ['93.184.216.34']),
        );
    }
}
