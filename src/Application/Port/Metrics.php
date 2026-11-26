<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Application\Metrics\Metric;
use Clavia\Application\Metrics\MetricSample;

/**
 * What this server measures (#23): counters and durations, shared by every process, read back for
 * exposition. Recording never fails the work it measures: an implementation that cannot keep a
 * sample drops it.
 */
interface Metrics
{
    /**
     * One occurrence.
     *
     * @param array<non-empty-string, string> $labels The metric's labels, each a bounded value.
     */
    public function count(Metric $metric, array $labels): void;

    /**
     * How long something took.
     *
     * @param array<non-empty-string, string> $labels
     */
    public function observe(Metric $metric, float $seconds, array $labels): void;

    /**
     * Everything recorded so far, by every process.
     *
     * @return list<MetricSample>
     */
    public function samples(): array;
}
