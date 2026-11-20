<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use PDOException;
use Throwable;

/**
 * Recognises which constraint a failed statement violated, so that a repository can
 * turn the one it expects into a domain answer and let every other failure through.
 *
 * Letting the constraint decide is what holds under concurrency: a "does it exist?"
 * query before the insert leaves a window in which another request inserts the same row.
 */
final class Constraint
{
    /** SQLSTATE `unique_violation`. */
    private const string UNIQUE_VIOLATION = '23505';

    private function __construct()
    {
    }

    /** Whether `$failure` is a violation of the unique constraint `$name`. */
    public static function isUniqueViolation(Throwable $failure, string $name): bool
    {
        for ($current = $failure; $current !== null; $current = $current->getPrevious()) {
            if (
                $current instanceof PDOException
                && (string) $current->getCode() === self::UNIQUE_VIOLATION
                && str_contains($current->getMessage(), '"' . $name . '"')
            ) {
                return true;
            }
        }

        return false;
    }
}
