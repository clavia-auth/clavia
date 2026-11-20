<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Closure;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A PSR-18 client with nothing on the wire: each request goes to a handler the test
 * writes, and is remembered. Nothing in the suite talks to a real provider.
 */
final class FakeHttpClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];

    /** @var Closure(RequestInterface): ResponseInterface */
    private Closure $handler;

    /**
     * @param callable(RequestInterface): ResponseInterface|null $handler 404 for everything when null.
     */
    public function __construct(?callable $handler = null)
    {
        $this->handler = $handler === null
            ? static fn (RequestInterface $request): ResponseInterface => new JsonResponse(['error' => 'none'], 404)
            : $handler(...);
    }

    /**
     * @param callable(RequestInterface): ResponseInterface $handler
     */
    public function answerWith(callable $handler): void
    {
        $this->handler = $handler(...);
    }

    #[\Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;

        return ($this->handler)($request);
    }

    /**
     * A handler answering by URL (without the query): a response, or a function of the
     * request; 404 for any other URL.
     *
     * @param array<string, ResponseInterface|callable(RequestInterface): ResponseInterface> $byUrl
     *
     * @return callable(RequestInterface): ResponseInterface
     */
    public static function routes(array $byUrl): callable
    {
        return static function (RequestInterface $request) use ($byUrl): ResponseInterface {
            $answer = $byUrl[(string) $request->getUri()->withQuery('')] ?? new JsonResponse(['error' => 'none'], 404);

            return $answer instanceof ResponseInterface ? $answer : $answer($request);
        };
    }

    /**
     * The form a request posted, decoded.
     *
     * @return array<string, string>
     */
    public static function form(RequestInterface $request): array
    {
        $body = $request->getBody();
        $body->rewind();
        parse_str($body->getContents(), $form);

        /** @var array<string, string> $form */
        return $form;
    }
}
