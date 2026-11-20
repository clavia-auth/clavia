<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Secrets;

use Clavia\Adapter\Primary\Cli\GenerateEncryptionKeyCommand;
use Clavia\Adapter\Secondary\Crypto\AesGcmSecretCipher;
use Clavia\Application\Secrets\GenerateEncryptionKey;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

final class GenerateEncryptionKeyTest extends TestCase
{
    public function testTheKeyIsBase64OfThirtyTwoRandomBytes(): void
    {
        $key = new GenerateEncryptionKey(new SeededRandomSource(3))();

        self::assertSame(new SeededRandomSource(3)->bytes(32), base64_decode($key, true));
    }

    public function testEachCallGivesANewKey(): void
    {
        $generate = new GenerateEncryptionKey(new SeededRandomSource());

        self::assertNotSame($generate(), $generate());
    }

    public function testAGeneratedKeyIsOneTheCipherAccepts(): void
    {
        $random = new SeededRandomSource();
        $cipher = new AesGcmSecretCipher(new GenerateEncryptionKey($random)(), $random);

        self::assertSame('a seed', $cipher->decrypt($cipher->encrypt('a seed', 'ctx'), 'ctx'));
    }

    public function testTheCommandPrintsALineReadyForDotEnv(): void
    {
        $generate = new GenerateEncryptionKey(new SeededRandomSource());
        $tester = new CommandTester(new GenerateEncryptionKeyCommand($generate));
        $tester->execute([]);

        self::assertMatchesRegularExpression(
            '#^CLAVIA_SECRET_ENCRYPTION_KEY=[A-Za-z0-9+/]{43}=\n$#D',
            $tester->getDisplay(true),
        );
    }
}
