<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\PasswordHasher;
use ClaviaTest\Support\Contract\PasswordHasherContract;
use ClaviaTest\Support\Fake\FakePasswordHasher;

final class FakePasswordHasherTest extends PasswordHasherContract
{
    #[\Override]
    protected function hasher(): PasswordHasher
    {
        return new FakePasswordHasher();
    }
}
