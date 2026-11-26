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

/**
 * `GET /metrics` on the internal listener: every metric of the catalogue, with whatever has been
 * recorded of it, for Prometheus to scrape. A metric nothing was recorded for is still described.
 */
final readonly class ReadMetrics
{
    public function __construct(private Metrics $metrics)
    {
    }

    /** @return array{metrics: list<Metric>, samples: list<MetricSample>} */
    public function __invoke(): array
    {
        return ['metrics' => Metric::cases(), 'samples' => $this->metrics->samples()];
    }
}
