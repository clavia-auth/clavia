<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\AttemptCounter;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see AttemptCounter} must do. Expiry is asserted by each implementation's
 * own test.
 */
trait AttemptCounterContract
{
    abstract protected function counter(): AttemptCounter;

    #[Test]
    public function anUnknownSubjectHasNoFailures(): void
    {
        self::assertSame(0, $this->counter()->count('account:nobody@example.com'));
    }

    #[Test]
    public function eachFailureCountsOnceForItsOwnSubject(): void
    {
        $this->counter()->increment('account:jane@example.com', 900);
        $this->counter()->increment('account:jane@example.com', 900);
        $this->counter()->increment('address:203.0.113.7', 900);

        self::assertSame(2, $this->counter()->count('account:jane@example.com'));
        self::assertSame(1, $this->counter()->count('address:203.0.113.7'));
        self::assertSame(0, $this->counter()->count('account:JANE@example.com'));
    }

    #[Test]
    public function resettingClearsTheNamedSubjectsAndOnlyThose(): void
    {
        $this->counter()->increment('a', 900);
        $this->counter()->increment('b', 900);
        $this->counter()->increment('c', 900);

        $this->counter()->reset('a', 'b', 'never-counted');
        $this->counter()->reset();

        self::assertSame(0, $this->counter()->count('a'));
        self::assertSame(0, $this->counter()->count('b'));
        self::assertSame(1, $this->counter()->count('c'));
    }
}
