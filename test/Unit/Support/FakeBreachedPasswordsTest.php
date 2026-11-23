<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\BreachedPasswords;
use ClaviaTest\Support\Contract\BreachedPasswordsContract;
use ClaviaTest\Support\Fake\FakeBreachedPasswords;

final class FakeBreachedPasswordsTest extends BreachedPasswordsContract
{
    #[\Override]
    protected function corpus(array $breached): BreachedPasswords
    {
        return new FakeBreachedPasswords($breached);
    }

    #[\Override]
    protected function unavailableCorpus(): BreachedPasswords
    {
        return FakeBreachedPasswords::unavailable();
    }
}
