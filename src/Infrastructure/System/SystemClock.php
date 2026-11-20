<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Infrastructure\System;

use Clavia\Domain\Shared\Clock;
use DateTimeImmutable;
use DateTimeZone;

/**
 * The machine's clock, always read in UTC whatever `date.timezone` says.
 */
final readonly class SystemClock implements Clock
{
    #[\Override]
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}
