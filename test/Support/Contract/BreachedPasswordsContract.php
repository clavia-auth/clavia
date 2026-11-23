<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\BreachCheckUnavailable;
use Clavia\Application\Port\BreachedPasswords;
use PHPUnit\Framework\TestCase;

/**
 * What every {@see BreachedPasswords} must do — the real adapter and the test double alike.
 */
abstract class BreachedPasswordsContract extends TestCase
{
    /**
     * A corpus that knows exactly these passwords.
     *
     * @param list<string> $breached
     */
    abstract protected function corpus(array $breached): BreachedPasswords;

    /** A corpus that cannot be asked. */
    abstract protected function unavailableCorpus(): BreachedPasswords;

    public function testAKnownPasswordIsBreached(): void
    {
        self::assertTrue($this->corpus(['password123', 'hunter22'])->isBreached('hunter22'));
    }

    public function testAnUnknownPasswordIsNot(): void
    {
        $corpus = $this->corpus(['password123']);

        self::assertFalse($corpus->isBreached('correct horse battery staple'));
        // Exact: neither the case nor a prefix is the same password.
        self::assertFalse($corpus->isBreached('PASSWORD123'));
        self::assertFalse($corpus->isBreached('password12'));
    }

    public function testAnUnavailableCorpusSaysSo(): void
    {
        $this->expectException(BreachCheckUnavailable::class);

        $_ = $this->unavailableCorpus()->isBreached('password123');
    }
}
