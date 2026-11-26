<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Metrics;

use Clavia\Application\Port\Metrics;

/** `CLAVIA_METRICS_ENABLED=false`: nothing is measured, and nothing is written for it. */
final readonly class NoMetrics implements Metrics
{
    #[\Override]
    public function count(Metric $metric, array $labels): void
    {
    }

    #[\Override]
    public function observe(Metric $metric, float $seconds, array $labels): void
    {
    }

    #[\Override]
    public function samples(): array
    {
        return [];
    }
}
