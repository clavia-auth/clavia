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
use Clavia\Application\Metrics\MetricSample;
use Clavia\Application\Metrics\ReadMetrics;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\Response\TextResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /metrics` (#23): what this server measured, in Prometheus's text exposition format 0.0.4.
 *
 * Only on the internal listener: Caddy's `:8081` site passes the FastCGI parameter
 * `CLAVIA_LISTENER=internal`, which a client cannot set (its headers reach PHP as `HTTP_*`), and
 * every other request is `404`, as at Caddy on both public hosts. The numbers are no secret, but
 * they say how busy the server is and what fails, which is nobody else's business.
 */
final readonly class MetricsHandler implements RequestHandlerInterface
{
    public const string LISTENER_PARAMETER = 'CLAVIA_LISTENER';

    private const string CONTENT_TYPE = 'text/plain; version=0.0.4; charset=utf-8';

    public function __construct(
        private ReadMetrics $read,
        private bool $enabled,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if (! $this->enabled || ($request->getServerParams()[self::LISTENER_PARAMETER] ?? null) !== 'internal') {
            return new TextResponse('', StatusCodeInterface::STATUS_NOT_FOUND, ['Cache-Control' => 'no-store']);
        }
        $read = ($this->read)();

        return new TextResponse(
            self::exposition($read['metrics'], $read['samples']),
            StatusCodeInterface::STATUS_OK,
            ['Content-Type' => self::CONTENT_TYPE, 'Cache-Control' => 'no-store'],
        );
    }

    /**
     * @param list<Metric>       $metrics
     * @param list<MetricSample> $samples
     */
    public static function exposition(array $metrics, array $samples): string
    {
        $lines = [];
        foreach ($metrics as $metric) {
            $name = $metric->name();
            $lines[] = sprintf('# HELP %s %s', $name, $metric->help());
            $lines[] = sprintf('# TYPE %s %s', $name, $metric->isHistogram() ? 'histogram' : 'counter');
            foreach ($samples as $sample) {
                if ($sample->metric !== $metric) {
                    continue;
                }
                if (! $metric->isHistogram()) {
                    $lines[] = $name . self::labels($sample->labels) . ' ' . self::number($sample->value);
                    continue;
                }
                foreach ($sample->buckets as [$bound, $count]) {
                    $bucket = self::labels($sample->labels + ['le' => $bound]);
                    $lines[] = $name . '_bucket' . $bucket . ' ' . $count;
                }
                $lines[] = $name . '_sum' . self::labels($sample->labels) . ' ' . self::number($sample->value);
                $lines[] = $name . '_count' . self::labels($sample->labels) . ' ' . $sample->count;
            }
        }

        return implode("\n", $lines) . "\n";
    }

    /** @param array<string, string> $labels */
    private static function labels(array $labels): string
    {
        if ($labels === []) {
            return '';
        }
        $pairs = [];
        foreach ($labels as $name => $value) {
            $pairs[] = $name . '="' . str_replace(['\\', '"', "\n"], ['\\\\', '\\"', '\\n'], $value) . '"';
        }

        return '{' . implode(',', $pairs) . '}';
    }

    private static function number(float $value): string
    {
        return floor($value) === $value && abs($value) < 1e15 ? (string) (int) $value : (string) $value;
    }
}
