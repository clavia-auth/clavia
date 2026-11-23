<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\DpopNonces;
use ClaviaTest\Support\Fake\FrozenClock;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see DpopNonces} must do — the Redis adapter and the double. Windows of 300 s.
 */
trait DpopNoncesContract
{
    abstract protected function nonces(FrozenClock $clock): DpopNonces;

    #[Test]
    public function theCurrentNonceIsStableWithinItsWindowAndAcceptedOneWindowMore(): void
    {
        $clock = new FrozenClock('2026-01-15T10:00:00Z');
        $nonces = $this->nonces($clock);

        $nonce = $nonces->current();
        self::assertNotSame('', $nonce);
        self::assertSame($nonce, $nonces->current());
        self::assertTrue($nonces->isCurrent($nonce));

        $clock->advance(300);
        self::assertNotSame($nonce, $nonces->current());
        self::assertTrue($nonces->isCurrent($nonce), 'The previous window is still accepted.');

        $clock->advance(300);
        $nonces->current();
        self::assertFalse($nonces->isCurrent($nonce));
    }

    #[Test]
    public function aNonceThisServerDidNotGiveIsNotCurrent(): void
    {
        $nonces = $this->nonces(new FrozenClock());
        $nonces->current();

        self::assertFalse($nonces->isCurrent('made-up'));
        self::assertFalse($nonces->isCurrent(''));
    }
}
