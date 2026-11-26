<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Metrics\LabelValue;
use Clavia\Application\Metrics\Metric;
use Clavia\Application\Metrics\MetricSample;
use Clavia\Application\Port\Metrics;
use Closure;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Metrics in Redis, shared by every PHP-FPM process: `metrics:<name>` is a hash whose fields are a
 * series' labels (`grant_type=authorization_code`), holding its count. A histogram's series has a
 * field per bucket (`…|le=0.1`, cumulative, so each is what Prometheus exposes), its sum and its
 * count.
 *
 * A request's samples are kept in memory and written in one pipeline by {@see flush()}: the first
 * sample after a flush asks `$schedule` for one, which the composition root runs after the response
 * is out, so measuring adds no round trip to the person's wait, however long the process lives. A
 * failure to write is logged and the samples dropped, never raised.
 */
final class RedisMetrics implements Metrics
{
    private const string PREFIX = 'metrics';

    /** @var list<array{0: string, 1: string, 2: int|float}> Key, field, amount. */
    private array $pending = [];

    /**
     * @param (Closure(Closure(): void): void)|null $schedule Asked to run a flush later; none flushes at once.
     */
    public function __construct(
        private readonly RedisConnection $redis,
        private readonly LoggerInterface $logger,
        private readonly ?Closure $schedule = null,
    ) {
    }

    #[\Override]
    public function count(Metric $metric, array $labels): void
    {
        $this->add([self::key($metric), self::series($metric, $labels), 1]);
    }

    #[\Override]
    public function observe(Metric $metric, float $seconds, array $labels): void
    {
        $key = self::key($metric);
        $series = self::series($metric, $labels);
        $writes = [];
        foreach ($metric->buckets() as $bound) {
            if ($seconds <= $bound) {
                $writes[] = [$key, $series . '|le=' . self::bound($bound), 1];
            }
        }
        $this->add(
            ...$writes,
            ...[[$key, $series . '|le=+Inf', 1], [$key, $series . '|sum', $seconds], [$key, $series . '|count', 1]],
        );
    }

    /** @param array{0: string, 1: string, 2: int|float} ...$writes */
    private function add(array ...$writes): void
    {
        $first = $this->pending === [];
        foreach ($writes as $write) {
            $this->pending[] = $write;
        }
        if (! $first) {
            return;
        }
        if ($this->schedule === null) {
            $this->flush();
        } else {
            ($this->schedule)($this->flush(...));
        }
    }

    /** Write what this process recorded, in one pipeline. */
    public function flush(): void
    {
        if ($this->pending === []) {
            return;
        }
        $pending = $this->pending;
        $this->pending = [];
        try {
            $client = $this->redis->client();
            $client->multi(\Redis::PIPELINE);
            foreach ($pending as [$key, $field, $amount]) {
                if (is_int($amount)) {
                    $client->hIncrBy($key, $field, $amount);
                } else {
                    $client->hIncrByFloat($key, $field, $amount);
                }
            }
            $client->exec();
        } catch (Throwable $failure) {
            $this->logger->warning('Metrics could not be written: {failure}', ['failure' => $failure::class]);
        }
    }

    #[\Override]
    public function samples(): array
    {
        $samples = [];
        foreach (Metric::cases() as $metric) {
            /** @var array<string, string>|false $fields */
            $fields = $this->redis->client()->hGetAll(self::key($metric));
            $samples = [...$samples, ...self::read($metric, is_array($fields) ? $fields : [])];
        }

        return $samples;
    }

    /**
     * @param array<string, string> $fields
     *
     * @return list<MetricSample>
     */
    private static function read(Metric $metric, array $fields): array
    {
        /** @var array<string, array{fields: array<string, string>, value: string}> $series */
        $series = [];
        foreach ($fields as $field => $value) {
            $parts = explode('|', $field, 2);
            $labels = $parts[0];
            $series[$labels] ??= ['fields' => [], 'value' => '0'];
            if (isset($parts[1])) {
                $series[$labels]['fields'][$parts[1]] = $value;
            } else {
                $series[$labels]['value'] = $value;
            }
        }
        $samples = [];
        foreach ($series as $labels => $recorded) {
            $decoded = self::labels($metric, $labels);
            if (! $metric->isHistogram()) {
                $samples[] = new MetricSample($metric, $decoded, (float) $recorded['value']);
                continue;
            }
            $buckets = [];
            foreach ([...array_map(self::bound(...), $metric->buckets()), '+Inf'] as $bound) {
                $buckets[] = [$bound, (int) ($recorded['fields']['le=' . $bound] ?? 0)];
            }
            $samples[] = new MetricSample(
                $metric,
                $decoded,
                (float) ($recorded['fields']['sum'] ?? 0),
                $buckets,
                (int) ($recorded['fields']['count'] ?? 0),
            );
        }

        return $samples;
    }

    private static function key(Metric $metric): string
    {
        return Keys::forIdentifier(self::PREFIX, $metric->name());
    }

    /** @param array<non-empty-string, string> $labels */
    private static function series(Metric $metric, array $labels): string
    {
        return implode(',', array_map(
            static fn (string $name): string => $name . '=' . LabelValue::of($labels[$name] ?? ''),
            $metric->labels(),
        ));
    }

    /** @return array<non-empty-string, string> */
    private static function labels(Metric $metric, string $series): array
    {
        $values = [];
        foreach (explode(',', $series) as $pair) {
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
            if ($name !== '' && in_array($name, $metric->labels(), true)) {
                $values[$name] = $value;
            }
        }

        return $values;
    }

    private static function bound(float $bound): string
    {
        return rtrim(rtrim(sprintf('%.3f', $bound), '0'), '.');
    }
}
