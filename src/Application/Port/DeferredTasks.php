<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Closure;

/**
 * Work that must happen because of a request, but that the person making it should not
 * wait for: telling other servers about it.
 *
 * Deferred work runs after the response has been sent, in the same process — without a
 * queue, so a deployment needs nothing more than PHP-FPM — and is best effort: a task
 * that fails is logged and does not stop the next one. A queue can replace the adapter
 * without anything here changing.
 */
interface DeferredTasks
{
    /**
     * @param Closure(): void $task Runs once, after the response; it must not depend on the
     *                              request's state, which is gone by then.
     */
    public function defer(Closure $task): void;
}
