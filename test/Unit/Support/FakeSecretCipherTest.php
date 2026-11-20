<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\EncryptionUnavailable;
use Clavia\Application\Port\SecretCipher;
use ClaviaTest\Support\Contract\SecretCipherContract;
use ClaviaTest\Support\Fake\FakeSecretCipher;

final class FakeSecretCipherTest extends SecretCipherContract
{
    #[\Override]
    protected function cipher(): SecretCipher
    {
        return new FakeSecretCipher();
    }

    public function testItCanPlayAServerWithNoKeyConfigured(): void
    {
        $cipher = new FakeSecretCipher();
        $cipher->available = false;

        $this->expectException(EncryptionUnavailable::class);

        $cipher->encrypt('x', 'ctx');
    }
}
