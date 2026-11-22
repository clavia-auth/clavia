<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Http;

use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Adapter\Secondary\Http\PinCheckedAddresses;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Promise\FulfilledPromise;
use GuzzleHttp\Promise\PromiseInterface;
use Laminas\Diactoros\Request;
use Laminas\Diactoros\Response\EmptyResponse;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * The fetch goes to the addresses the policy checked, and a refused URL is never sent.
 */
final class PinCheckedAddressesTest extends TestCase
{
    /** @var list<array<string, mixed>> The options each request reached the handler with. */
    private array $sent = [];

    public function testTheCheckedAddressesArePinnedForCurl(): void
    {
        $this->send('https://idp.example/token', ['93.184.216.34', '2606:2800:220:1::248'])->wait();

        self::assertSame(
            ['idp.example:443:93.184.216.34,[2606:2800:220:1::248]'],
            $this->pinned(0),
        );
    }

    public function testAnExplicitPortIsPinned(): void
    {
        $this->send('https://idp.example:8443/token', ['93.184.216.34'])->wait();

        self::assertSame(['idp.example:8443:93.184.216.34'], $this->pinned(0));
    }

    public function testAnIpLiteralOrAnUnresolvedNameHasNothingToPin(): void
    {
        $this->send('https://93.184.216.34/token', ['10.0.0.1'])->wait();
        $this->send('https://nowhere.example/token', [])->wait();

        self::assertArrayNotHasKey('curl', $this->sent[0]);
        self::assertArrayNotHasKey('curl', $this->sent[1]);
    }

    public function testARefusedUrlIsNotSentAndFailsAsUnreachable(): void
    {
        $promise = $this->send('https://idp.example/token', ['169.254.169.254']);

        try {
            $promise->wait();
            self::fail('A request to the metadata service was sent.');
        } catch (ConnectException $refused) {
            self::assertStringContainsString('internal host', $refused->getMessage());
            self::assertSame([], $this->sent);
        }
    }

    public function testPlainHttpIsNeverSent(): void
    {
        $this->expectException(ConnectException::class);

        $this->send('http://idp.example/token', ['93.184.216.34'])->wait();
    }

    /** What request number `$index` was pinned to: its `CURLOPT_RESOLVE` option. */
    private function pinned(int $index): mixed
    {
        /** @var mixed $curl */
        $curl = $this->sent[$index]['curl'] ?? null;

        return is_array($curl) ? ($curl[CURLOPT_RESOLVE] ?? null) : null;
    }

    /**
     * @param list<string> $resolvesTo
     */
    private function send(string $url, array $resolvesTo): PromiseInterface
    {
        $middleware = new PinCheckedAddresses(new OutboundUrlPolicy(false, static fn (): array => $resolvesTo));
        $handler = $middleware(
            /** @return PromiseInterface<ResponseInterface, mixed> */
            function (RequestInterface $request, array $options): PromiseInterface {
                /** @var array<string, mixed> $options */
                $this->sent[] = $options;
                /** @var FulfilledPromise<ResponseInterface, mixed> $answered */
                $answered = new FulfilledPromise(new EmptyResponse());

                return $answered;
            },
        );

        $promise = $handler(new Request($url, 'POST'), []);
        self::assertInstanceOf(PromiseInterface::class, $promise);

        return $promise;
    }
}
