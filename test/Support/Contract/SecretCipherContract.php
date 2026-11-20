<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\SecretCipher;
use PHPUnit\Framework\TestCase;

/**
 * What every {@see SecretCipher} must do — the real adapter and the test double alike.
 */
abstract class SecretCipherContract extends TestCase
{
    abstract protected function cipher(): SecretCipher;

    public function testWhatIsEncryptedCanBeReadBackUnderTheSameContext(): void
    {
        $cipher = $this->cipher();
        $plaintext = "-----BEGIN PRIVATE KEY-----\nMIIEvQ…\n-----END PRIVATE KEY-----\n";

        $sealed = $cipher->encrypt($plaintext, 'kid:2026-11');

        self::assertSame($plaintext, $cipher->decrypt($sealed, 'kid:2026-11'));
    }

    public function testBinaryAndEmptyPlaintextsSurvive(): void
    {
        $cipher = $this->cipher();
        $binary = "\x00\xff\x10 seed \x80";

        self::assertSame($binary, $cipher->decrypt($cipher->encrypt($binary, 'ctx'), 'ctx'));
        self::assertSame('', $cipher->decrypt($cipher->encrypt('', 'ctx'), 'ctx'));
    }

    public function testTheCiphertextIsPrintableAndDoesNotContainThePlaintext(): void
    {
        $sealed = $this->cipher()->encrypt('JBSWY3DPEHPK3PXP', 'user:42:totp');

        self::assertMatchesRegularExpression('#^[A-Za-z0-9+/]+=*$#D', $sealed);
        self::assertStringNotContainsString('JBSWY3DPEHPK3PXP', $sealed);
    }

    public function testEncryptingTwiceGivesTwoCiphertexts(): void
    {
        $cipher = $this->cipher();

        self::assertNotSame($cipher->encrypt('same', 'ctx'), $cipher->encrypt('same', 'ctx'));
    }

    public function testACiphertextCannotBeMovedToAnotherContext(): void
    {
        $cipher = $this->cipher();
        $sealed = $cipher->encrypt('seed-of-user-1', 'user:1:totp');

        $this->expectException(DecryptionFailed::class);

        $cipher->decrypt($sealed, 'user:2:totp');
    }

    public function testATamperedCiphertextIsRefused(): void
    {
        $cipher = $this->cipher();
        $raw = (string) base64_decode($cipher->encrypt('a secret value', 'ctx'), true);
        $middle = intdiv(strlen($raw), 2);
        $raw[$middle] = chr(ord($raw[$middle]) ^ 0x01);

        $this->expectException(DecryptionFailed::class);

        $cipher->decrypt(base64_encode($raw), 'ctx');
    }

    public function testGarbageIsRefused(): void
    {
        $refused = 0;
        foreach (['', 'not base64 at all!', 'AAAA', base64_encode('short')] as $garbage) {
            try {
                $this->cipher()->decrypt($garbage, 'ctx');
            } catch (DecryptionFailed) {
                $refused++;
            }
        }

        self::assertSame(4, $refused);
    }
}
