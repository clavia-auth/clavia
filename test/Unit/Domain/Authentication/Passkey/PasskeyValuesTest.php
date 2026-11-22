<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Authentication\Passkey;

use Clavia\Domain\Authentication\Passkey\Aaguid;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\CosePublicKey;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The values a passkey is made of, each refusing what the specification or the page cannot hold.
 */
final class PasskeyValuesTest extends TestCase
{
    public function testACredentialIdIsSixteenToTheThousandAndTwentyThreeBytes(): void
    {
        self::assertSame(16, strlen(CredentialId::fromBytes(str_repeat("\x00", 16))->bytes()));
        self::assertSame(1023, strlen(CredentialId::fromBytes(str_repeat("\xff", 1023))->bytes()));

        foreach ([0, 15, 1024] as $length) {
            try {
                CredentialId::fromBytes(str_repeat('a', $length));
                self::fail($length . ' bytes were accepted.');
            } catch (InvalidValue $refusal) {
                self::assertNotSame('', $refusal->getMessage());
            }
        }
    }

    public function testACredentialIdTravelsAsUnpaddedBase64Url(): void
    {
        $bytes = "\x00\xfb\xff" . str_repeat("\x10", 14);
        $id = CredentialId::fromBytes($bytes);

        self::assertSame(rtrim(strtr(base64_encode($bytes), '+/', '-_'), '='), $id->toBase64Url());
        self::assertTrue(CredentialId::fromBase64Url($id->toBase64Url())->equals($id));
    }

    #[DataProvider('notBase64Url')]
    public function testACredentialIdThatIsNotBase64UrlIsRefused(string $encoded): void
    {
        $this->expectException(InvalidValue::class);

        CredentialId::fromBase64Url($encoded);
    }

    /** @return iterable<string, array{string}> */
    public static function notBase64Url(): iterable
    {
        yield 'padded' => ['AAAAAAAAAAAAAAAAAAAAAA=='];
        yield 'standard alphabet' => ['AAAA+AAAAAAAAAAAAAAAAA'];
        yield 'too short once decoded' => ['AAAA'];
        yield 'whitespace' => ["AAAAAAAAAAAAAAAAAAAAAA\n"];
    }

    public function testTwoCredentialIdsAreEqualByTheirBytes(): void
    {
        $a = CredentialId::fromBytes(str_repeat('a', 16));

        self::assertTrue($a->equals(CredentialId::fromBytes(str_repeat('a', 16))));
        self::assertFalse($a->equals(CredentialId::fromBytes(str_repeat('b', 16))));
    }

    public function testAPublicKeyIsOneToFourThousandAndNinetySixBytes(): void
    {
        self::assertSame("\xa5", CosePublicKey::fromBytes("\xa5")->bytes());
        self::assertSame(4096, strlen(CosePublicKey::fromBytes(str_repeat("\x01", 4096))->bytes()));

        foreach (['', str_repeat("\x01", 4097)] as $bytes) {
            try {
                CosePublicKey::fromBytes($bytes);
                self::fail('A key of ' . strlen($bytes) . ' bytes was accepted.');
            } catch (InvalidValue $refusal) {
                self::assertNotSame('', $refusal->getMessage());
            }
        }
    }

    public function testTheOfferedAlgorithmsAreEdDsaThenEs256ThenRs256(): void
    {
        self::assertSame([-8, -7, -257], array_map(
            static fn (CoseAlgorithm $algorithm): int => $algorithm->value,
            CoseAlgorithm::preferred(),
        ));
        self::assertSame(CoseAlgorithm::ES256, CoseAlgorithm::fromIdentifier(-7));
    }

    public function testAnAlgorithmThatIsNotOfferedIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        CoseAlgorithm::fromIdentifier(-35);
    }

    public function testAnAaguidIsALowerCaseUuidAndAllZerosIsNoneAtAll(): void
    {
        $bytes = hex2bin('adce000235bcc60a648b0b25f1f05503');
        self::assertIsString($bytes);

        self::assertSame('adce0002-35bc-c60a-648b-0b25f1f05503', Aaguid::fromBytes($bytes)?->value);
        self::assertSame(
            'adce0002-35bc-c60a-648b-0b25f1f05503',
            Aaguid::fromString('adce0002-35bc-c60a-648b-0b25f1f05503')->value,
        );
        self::assertNull(Aaguid::fromBytes(str_repeat("\x00", 16)));
    }

    #[DataProvider('notAnAaguid')]
    public function testAnAaguidThatIsNotOneIsRefused(string $value): void
    {
        $this->expectException(InvalidValue::class);

        Aaguid::fromString($value);
    }

    /** @return iterable<string, array{string}> */
    public static function notAnAaguid(): iterable
    {
        yield 'upper case' => ['ADCE0002-35BC-C60A-648B-0B25F1F05503'];
        yield 'no hyphens' => ['adce000235bcc60a648b0b25f1f05503'];
        yield 'all zeros' => ['00000000-0000-0000-0000-000000000000'];
        yield 'a trailing newline' => ["adce0002-35bc-c60a-648b-0b25f1f05503\n"];
    }

    public function testAnAaguidFromTheWrongNumberOfBytesIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        Aaguid::fromBytes('short');
    }

    public function testANameIsTrimmedAndKeptAsTyped(): void
    {
        self::assertSame('Work laptop — Zürich 🔑', PasskeyName::fromString("  Work laptop — Zürich 🔑 \n")->value);
        self::assertSame(64, mb_strlen(PasskeyName::fromString(str_repeat('é', 64))->value));
    }

    #[DataProvider('notAName')]
    public function testANameThatCannotBePrintedBackIsRefused(string $value): void
    {
        $this->expectException(InvalidValue::class);

        PasskeyName::fromString($value);
    }

    /** @return iterable<string, array{string}> */
    public static function notAName(): iterable
    {
        yield 'empty' => [''];
        yield 'only whitespace' => ["  \t "];
        yield 'too long' => [str_repeat('a', 65)];
        yield 'a newline inside' => ["Work\nlaptop"];
        yield 'a NUL' => ["Work\0laptop"];
        yield 'a bidirectional override' => ["Work \u{202E}laptop"];
        yield 'a line separator' => ["Work\u{2028}laptop"];
        yield 'not UTF-8' => ["Work \xff laptop"];
    }
}
