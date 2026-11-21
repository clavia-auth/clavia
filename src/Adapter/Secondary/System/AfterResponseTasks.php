<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\System;

use Clavia\Application\Port\DeferredTasks;
use Closure;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Deferred work kept in memory and run by the entry point once the response is out:
 * `public/index.php` hands the response to PHP-FPM, calls `fastcgi_finish_request()` so
 * the browser has it, then {@see self::run()}. The worker stays busy a little longer; the
 * person does not wait.
 *
 * Each task runs once and on its own: one that throws is logged, and the next one runs.
 */
final class AfterResponseTasks implements DeferredTasks
{
    /** @var list<Closure(): void> */
    private array $tasks = [];

    public function __construct(private readonly LoggerInterface $logger)
    {
    }

    #[\Override]
    public function defer(Closure $task): void
    {
        $this->tasks[] = $task;
    }

    /** Run what was deferred, in order, emptying the list — including tasks deferred meanwhile. */
    public function run(): void
    {
        while ($this->tasks !== []) {
            $task = array_shift($this->tasks);
            try {
                $task();
            } catch (Throwable $failure) {
                $this->logger->error('A task deferred until after the response failed: {failure}', [
                    'failure' => $failure::class . ': ' . $failure->getMessage(),
                    'exception' => $failure,
                ]);
            }
        }
    }

    /** How many tasks are waiting — for tests. */
    public function count(): int
    {
        return count($this->tasks);
    }
}
