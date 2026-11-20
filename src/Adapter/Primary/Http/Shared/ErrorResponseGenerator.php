<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Turns an uncaught error into a response that says nothing about it.
 *
 * The cause goes to the log and never to the client, in every environment: an
 * identity provider's stack trace names its tables, its keys' identifiers and the
 * code path an attacker just reached. `no-store` keeps the failure out of caches.
 */
final readonly class ErrorResponseGenerator
{
    public function __construct(
        private StreamFactoryInterface $streams,
        private LoggerInterface $logger,
    ) {
    }

    public function __invoke(
        Throwable $error,
        ServerRequestInterface $request,
        ResponseInterface $response,
    ): ResponseInterface {
        $this->logger->error('Uncaught error while handling {method} {path}: {message}', [
            'method' => $request->getMethod(),
            'path' => $request->getUri()->getPath(),
            'message' => $error->getMessage(),
            'exception' => $error,
        ]);

        return $response
            ->withStatus(500)
            ->withHeader('Content-Type', 'text/plain; charset=utf-8')
            ->withHeader('Cache-Control', 'no-store')
            ->withBody($this->streams->createStream('Internal Server Error'));
    }
}
