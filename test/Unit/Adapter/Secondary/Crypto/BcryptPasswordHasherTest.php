<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Crypto;

use Clavia\Adapter\Secondary\Crypto\BcryptPasswordHasher;
use Clavia\Application\Port\PasswordHasher;
use ClaviaTest\Support\Contract\PasswordHasherContract;

final class BcryptPasswordHasherTest extends PasswordHasherContract
{
    /** The lowest cost bcrypt accepts: these tests are about behaviour, not about being slow. */
    private const int TEST_COST = 4;

    #[\Override]
    protected function hasher(): PasswordHasher
    {
        return new BcryptPasswordHasher(self::TEST_COST);
    }

    public function testItProducesABcryptHashAtTheConfiguredCost(): void
    {
        self::assertMatchesRegularExpression(
            '#^\$2y\$04\$[./A-Za-z0-9]{53}$#D',
            new BcryptPasswordHasher(4)->hash('a-secret'),
        );
        self::assertStringStartsWith('$2y$12$', new BcryptPasswordHasher()->hash('a-secret'));
    }

    public function testItVerifiesTheBcryptReferenceVector(): void
    {
        // The OpenBSD reference vector for "U*U", with the $2b$ prefix.
        $reference = '$2b$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW';

        self::assertTrue($this->hasher()->verify('U*U', $reference));
        self::assertFalse($this->hasher()->verify('U*V', $reference));
    }

    public function testAHashAtALowerCostNeedsARehash(): void
    {
        $weak = new BcryptPasswordHasher(4)->hash('a-secret');
        $current = new BcryptPasswordHasher(5);

        self::assertTrue($current->verify('a-secret', $weak));
        self::assertTrue($current->needsRehash($weak));
        self::assertFalse($current->needsRehash($current->hash('a-secret')));
    }

    public function testAHashFromAnotherAlgorithmNeedsARehash(): void
    {
        self::assertTrue($this->hasher()->needsRehash('$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub'));
    }
}
