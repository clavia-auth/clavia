<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\DpopReplayCache;
use Clavia\Domain\OAuth2\Dpop\JwkThumbprint;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see DpopReplayCache} must do — the Redis adapter and the double.
 */
trait DpopReplayCacheContract
{
    abstract protected function replays(): DpopReplayCache;

    #[Test]
    public function aProofIsAcceptedOncePerKey(): void
    {
        $key = JwkThumbprint::fromString('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
        $other = JwkThumbprint::fromString('AzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');

        self::assertTrue($this->replays()->claim($key, 'jti-1', 60));
        self::assertFalse($this->replays()->claim($key, 'jti-1', 60));
        self::assertTrue($this->replays()->claim($key, 'jti-2', 60));
        // Another key's jti is another proof.
        self::assertTrue($this->replays()->claim($other, 'jti-1', 60));
    }
}
