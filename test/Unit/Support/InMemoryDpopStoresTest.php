<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\DpopNonces;
use Clavia\Application\Port\DpopReplayCache;
use ClaviaTest\Support\Contract\DpopNoncesContract;
use ClaviaTest\Support\Contract\DpopReplayCacheContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryDpopNonces;
use ClaviaTest\Support\Fake\InMemoryDpopReplayCache;
use PHPUnit\Framework\TestCase;

final class InMemoryDpopStoresTest extends TestCase
{
    use DpopReplayCacheContract;
    use DpopNoncesContract;

    private ?InMemoryDpopReplayCache $replays = null;

    #[\Override]
    protected function replays(): DpopReplayCache
    {
        return $this->replays ??= new InMemoryDpopReplayCache(new FrozenClock());
    }

    #[\Override]
    protected function nonces(FrozenClock $clock): DpopNonces
    {
        return new InMemoryDpopNonces($clock, 300);
    }
}
