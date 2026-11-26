<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Clavia\Application\Metrics\Metric;
use Clavia\Application\Port\Metrics;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Mezzio\Router\RouteResult;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Throwable;

/**
 * Times every request (#23), by the route's name (never its path, which carries identifiers), the
 * method and the status. Piped after routing, so the route is known; a request whose handler throws
 * is counted as the `500` the error handler around it makes of it.
 */
final readonly class MetricsMiddleware implements MiddlewareInterface
{
    private const array METHODS = [
        RequestMethodInterface::METHOD_GET,
        RequestMethodInterface::METHOD_HEAD,
        RequestMethodInterface::METHOD_POST,
        RequestMethodInterface::METHOD_PUT,
        RequestMethodInterface::METHOD_PATCH,
        RequestMethodInterface::METHOD_DELETE,
        RequestMethodInterface::METHOD_OPTIONS,
    ];

    public function __construct(private Metrics $metrics)
    {
    }

    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $start = (int) hrtime(true);
        try {
            $response = $handler->handle($request);
        } catch (Throwable $failure) {
            $this->record($request, StatusCodeInterface::STATUS_INTERNAL_SERVER_ERROR, $start);

            throw $failure;
        }
        $this->record($request, $response->getStatusCode(), $start);

        return $response;
    }

    private function record(ServerRequestInterface $request, int $status, int $start): void
    {
        $this->metrics->observe(Metric::RequestDuration, ((int) hrtime(true) - $start) / 1_000_000_000, [
            'route' => self::route($request),
            'method' => in_array($request->getMethod(), self::METHODS, true) ? $request->getMethod() : 'other',
            'status' => (string) $status,
        ]);
    }

    private static function route(ServerRequestInterface $request): string
    {
        $result = $request->getAttribute(RouteResult::class);
        if (! $result instanceof RouteResult || $result->isFailure()) {
            return $result instanceof RouteResult && $result->isMethodFailure() ? 'method_not_allowed' : 'unmatched';
        }

        $name = $result->getMatchedRouteName();

        return is_string($name) && $name !== '' ? $name : 'unnamed';
    }
}
