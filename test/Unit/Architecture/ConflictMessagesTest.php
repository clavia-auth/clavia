<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Architecture;

use PHPUnit\Framework\TestCase;

/**
 * No error repeats the value at fault (CLAUDE.md, Management API): a `409` for something taken names its
 * kind, never the name, identifier or address sent (#167). A refusal's message is the problem's `detail`,
 * so one built from a string (`%s`) is refused here; a count (`%d`) says nothing of what was sent.
 */
final class ConflictMessagesTest extends TestCase
{
    public function testNoConflictMessageIsBuiltFromAString(): void
    {
        $offenders = [];
        foreach (SourceFiles::in(['src']) as $file) {
            $code = (string) file_get_contents($file);
            if (preg_match_all('/new (?:AlreadyExists|Conflict)\(\s*sprintf\(\s*([\'"])(?:(?!\1).)*%s/s', $code) > 0) {
                $offenders[] = substr($file, strlen(SourceFiles::PROJECT_ROOT) + 1);
            }
        }

        self::assertSame([], $offenders);
    }
}
