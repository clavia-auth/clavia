<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\System;

use ArrayObject;
use Clavia\Adapter\Secondary\System\AfterResponseTasks;
use ClaviaTest\Support\RecordingLogger;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class AfterResponseTasksTest extends TestCase
{
    public function testTasksRunOnceInOrderAndAFailureDoesNotStopTheNext(): void
    {
        $logger = new RecordingLogger();
        $tasks = new AfterResponseTasks($logger);
        /** @var ArrayObject<int, string> $ran */
        $ran = new ArrayObject();

        $tasks->defer(static function () use ($ran): void {
            $ran->append('first');
        });
        $tasks->defer(static function (): void {
            throw new RuntimeException('The relying party exploded.');
        });
        $tasks->defer(static function () use ($ran, $tasks): void {
            $ran->append('third');
            $tasks->defer(static function () use ($ran): void {
                $ran->append('deferred meanwhile');
            });
        });
        self::assertSame([], $ran->getArrayCopy(), 'Nothing runs until asked.');

        $tasks->run();
        $tasks->run();

        self::assertSame(['first', 'third', 'deferred meanwhile'], $ran->getArrayCopy());
        self::assertTrue($logger->hasRecordContaining('The relying party exploded.'));
        self::assertSame(0, $tasks->count());
    }
}
