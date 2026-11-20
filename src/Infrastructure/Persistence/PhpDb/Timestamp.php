<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Infrastructure\Persistence\PhpDb;

use DateTimeImmutable;
use DateTimeZone;

/**
 * Moves instants between the domain and `timestamptz` columns.
 *
 * Written with microseconds and an explicit offset, so the value means the same thing
 * whatever the session's time zone; read back into UTC.
 */
final class Timestamp
{
    private const string FORMAT = 'Y-m-d\TH:i:s.uP';

    private function __construct()
    {
    }

    public static function toDatabase(DateTimeImmutable $instant): string
    {
        return $instant->format(self::FORMAT);
    }

    public static function toDatabaseOrNull(?DateTimeImmutable $instant): ?string
    {
        return $instant?->format(self::FORMAT);
    }

    public static function fromDatabase(string $value): DateTimeImmutable
    {
        return new DateTimeImmutable($value)->setTimezone(new DateTimeZone('UTC'));
    }

    public static function fromDatabaseOrNull(?string $value): ?DateTimeImmutable
    {
        return $value === null ? null : self::fromDatabase($value);
    }
}
