<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Shared\Clock;
use DateInterval;
use DateTimeImmutable;
use DateTimeZone;

/**
 * A clock that stands still until a test moves it.
 */
final class FrozenClock implements Clock
{
    private DateTimeImmutable $now;

    public function __construct(string $at = '2026-01-15T10:00:00Z')
    {
        $this->now = new DateTimeImmutable($at)->setTimezone(new DateTimeZone('UTC'));
    }

    #[\Override]
    public function now(): DateTimeImmutable
    {
        return $this->now;
    }

    /** Move time forward by a number of seconds. */
    public function advance(int $seconds): void
    {
        $this->now = $this->now->add(new DateInterval('PT' . $seconds . 'S'));
    }

    public function setTo(string $at): void
    {
        $this->now = new DateTimeImmutable($at)->setTimezone(new DateTimeZone('UTC'));
    }
}
