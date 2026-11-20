<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Oidc;

use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\InvalidValue;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PublicJwkTest extends TestCase
{
    /** The RSA key of RFC 7638 §3.1 (also RFC 7517 Appendix A.1). */
    private const string N = '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1'
        . 'L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-'
        . '5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-'
        . '65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD0'
        . '8qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-'
        . 'kEgU8awapJzKnqDKgw';

    private const string E = 'AQAB';

    public function testTheKidIsTheRfc7638Thumbprint(): void
    {
        $jwk = $this->rfcKey();

        // RFC 7638 §3.1 gives the result.
        self::assertSame('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', $jwk->kid);
        // And an independent implementation agrees.
        self::assertSame(
            $jwk->kid,
            new JWK(['kty' => 'RSA', 'n' => self::N, 'e' => self::E])->thumbprint('sha256'),
        );
    }

    public function testItPublishesTheSigningKeyAndNothingElse(): void
    {
        self::assertSame(
            [
                'kty' => 'RSA',
                'use' => 'sig',
                'alg' => 'RS256',
                'kid' => 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
                'n' => self::N,
                'e' => self::E,
            ],
            $this->rfcKey()->toArray(),
        );
    }

    public function testLeadingZeroOctetsAreDroppedAsRfc7518Requires(): void
    {
        $padded = PublicJwk::rsa(
            "\0\0" . Base64Url::decode(self::N),
            "\0" . Base64Url::decode(self::E),
            SigningAlgorithm::RS256,
        );

        self::assertSame($this->rfcKey()->toArray(), $padded->toArray());
    }

    public function testAPublishedKeyReadsBackAsItself(): void
    {
        $jwk = $this->rfcKey();

        self::assertSame($jwk->toArray(), PublicJwk::fromArray($jwk->toArray())->toArray());
    }

    /**
     * @param array<string, string> $changes
     */
    #[DataProvider('notAPublicSigningKey')]
    public function testAnythingElseIsRefused(array $changes): void
    {
        $document = array_filter(
            [...$this->rfcKey()->toArray(), ...$changes],
            static fn (string $value): bool => $value !== '',
        );

        $this->expectException(InvalidValue::class);

        PublicJwk::fromArray($document);
    }

    /** @return iterable<string, array{array<string, string>}> */
    public static function notAPublicSigningKey(): iterable
    {
        yield 'a private exponent' => [[
            'd' => 'X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5f'
                . 'JLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUoh'
                . 'sXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IB'
                . 'TNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-'
                . 'Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q',
        ]];
        yield 'a prime' => [['p' => 'AQAB']];
        yield 'another key type' => [['kty' => 'EC']];
        yield 'an unsupported algorithm' => [['alg' => 'HS256']];
        yield 'no algorithm' => [['alg' => '']];
        yield 'an encryption key' => [['use' => 'enc']];
        yield 'a kid that is not the thumbprint' => [['kid' => 'chosen-by-someone']];
        yield 'a modulus that is not base64url' => [['n' => 'not base64url!']];
        yield 'no exponent' => [['e' => '']];
    }

    public function testAZeroModulusIsNotAKey(): void
    {
        $this->expectException(InvalidValue::class);

        PublicJwk::rsa("\0", "\x01\x00\x01", SigningAlgorithm::RS256);
    }

    private function rfcKey(): PublicJwk
    {
        return PublicJwk::rsa(Base64Url::decode(self::N), Base64Url::decode(self::E), SigningAlgorithm::RS256);
    }
}
