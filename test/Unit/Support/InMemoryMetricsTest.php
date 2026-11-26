<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\Metrics;
use ClaviaTest\Support\Contract\MetricsContract;
use ClaviaTest\Support\Fake\InMemoryMetrics;
use PHPUnit\Framework\TestCase;

final class InMemoryMetricsTest extends TestCase
{
    use MetricsContract;

    private InMemoryMetrics $metrics;

    #[\Override]
    protected function setUp(): void
    {
        $this->metrics = new InMemoryMetrics();
    }

    #[\Override]
    protected function metrics(): Metrics
    {
        return $this->metrics;
    }

    #[\Override]
    protected function flushMetrics(): void
    {
    }
}
