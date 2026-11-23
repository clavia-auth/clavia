<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\BreachCheckUnavailable;
use Clavia\Application\Port\BreachedPasswords;

/**
 * A breached-password corpus of the passwords a test names, or one that cannot be asked.
 */
final class FakeBreachedPasswords implements BreachedPasswords
{
    /** How many times the corpus was asked. */
    public int $asked = 0;

    /**
     * @param list<string> $breached
     */
    public function __construct(private readonly array $breached = [], private readonly bool $unavailable = false)
    {
    }

    public static function unavailable(): self
    {
        return new self([], true);
    }

    #[\Override]
    public function isBreached(#[\SensitiveParameter] string $password): bool
    {
        ++$this->asked;
        if ($this->unavailable) {
            throw new BreachCheckUnavailable('The corpus is down.');
        }

        return in_array($password, $this->breached, true);
    }
}
