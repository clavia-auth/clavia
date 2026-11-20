<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Psr\Log\AbstractLogger;
use Stringable;

/**
 * Keeps what the application logged, so a test can assert on it and the run stays quiet.
 *
 * @psalm-suppress ImmutableDependency A test double that records instead of writing out.
 */
final class RecordingLogger extends AbstractLogger
{
    /** @var list<array{level: mixed, message: string, context: array<array-key, mixed>}> */
    public array $records = [];

    /** @psalm-suppress ImmutableDependency */
    #[\Override]
    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = ['level' => $level, 'message' => (string) $message, 'context' => $context];
    }

    /**
     * Whether some record mentions `$text`, in its message or in a string of its context
     * (the error handler logs an exception's message there).
     */
    public function hasRecordContaining(string $text): bool
    {
        foreach ($this->records as $record) {
            $strings = [$record['message'], ...array_filter($record['context'], is_string(...))];
            foreach ($strings as $string) {
                if (str_contains($string, $text)) {
                    return true;
                }
            }
        }

        return false;
    }
}
