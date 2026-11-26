<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Http;

use Clavia\Adapter\Secondary\Http\HttpBackChannelLogoutDelivery;
use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\RecordingLogger;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\Response\EmptyResponse;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

final class HttpBackChannelLogoutDeliveryTest extends TestCase
{
    private FakeHttpClient $http;
    private RecordingLogger $logger;

    #[\Override]
    protected function setUp(): void
    {
        $this->http = new FakeHttpClient(
            static fn (): ResponseInterface => new EmptyResponse(StatusCodeInterface::STATUS_OK),
        );
        $this->logger = new RecordingLogger();
    }

    public function testTheTokenIsPostedAsAForm(): void
    {
        $this->delivery()->deliver(ClientId::fromString('spa'), Url::fromString('https://app.example/bc'), 'a.b.c');

        self::assertCount(1, $this->http->requests);
        $request = $this->http->requests[0];
        self::assertSame(RequestMethodInterface::METHOD_POST, $request->getMethod());
        self::assertSame('https://app.example/bc', (string) $request->getUri());
        self::assertSame('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        self::assertSame(['logout_token' => 'a.b.c'], FakeHttpClient::form($request));
        self::assertSame([], $this->logger->records);
    }

    public function testAnAddressThePolicyRefusesIsNotPostedToAndIsLogged(): void
    {
        $this->delivery(['10.0.0.5'])->deliver(
            ClientId::fromString('spa'),
            Url::fromString('https://intranet.example/bc'),
            'a.b.c',
        );

        self::assertSame([], $this->http->requests);
        self::assertTrue($this->logger->hasRecordContaining('must not point at this server'));
    }

    public function testARefusalIsLoggedWithoutTheToken(): void
    {
        $this->http->answerWith(
            static fn (): ResponseInterface => new EmptyResponse(StatusCodeInterface::STATUS_BAD_REQUEST),
        );

        $this->delivery()->deliver(
            ClientId::fromString('spa'),
            Url::fromString('https://app.example/bc'),
            'secret.token.x',
        );

        self::assertTrue($this->logger->hasRecordContaining('answered 400'));
        self::assertFalse($this->logger->hasRecordContaining('secret.token.x'));
    }

    /**
     * @param list<string> $addresses What every name resolves to.
     */
    private function delivery(array $addresses = ['93.184.216.34']): HttpBackChannelLogoutDelivery
    {
        return new HttpBackChannelLogoutDelivery(
            $this->http,
            new RequestFactory(),
            new StreamFactory(),
            new OutboundUrlPolicy(false, static fn (): array => $addresses),
            $this->logger,
        );
    }
}
