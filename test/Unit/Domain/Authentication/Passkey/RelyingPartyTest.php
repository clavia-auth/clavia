<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Authentication\Passkey;

use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The relying party: an id, an origin that belongs to it, and a name (WebAuthn Level 3 §5.4.2,
 * §13.4.1) — refused at startup where no browser would accept the pair.
 */
final class RelyingPartyTest extends TestCase
{
    public function testTheOriginMayBeTheIdOrASubdomainOfIt(): void
    {
        self::assertSame(
            'https://auth.example.com',
            RelyingParty::of('auth.example.com', 'Example', 'https://auth.example.com')->origin,
        );
        self::assertSame(
            'https://auth.example.com',
            RelyingParty::of('example.com', 'Example', 'https://auth.example.com')->origin,
        );
        self::assertSame(
            'https://auth.clavia.test:8443',
            RelyingParty::of('clavia.test', 'Clavia', 'https://auth.clavia.test:8443')->origin,
        );
    }

    public function testItKeepsWhatItWasGiven(): void
    {
        $rp = RelyingParty::of('auth.example.com', 'Example Inc.', 'https://auth.example.com');

        self::assertSame('auth.example.com', $rp->id);
        self::assertSame('Example Inc.', $rp->name);
    }

    #[DataProvider('refused')]
    public function testWhatNoBrowserWouldAcceptIsRefused(string $id, string $name, string $origin): void
    {
        $this->expectException(InvalidValue::class);

        RelyingParty::of($id, $name, $origin);
    }

    /** @return iterable<string, array{string, string, string}> */
    public static function refused(): iterable
    {
        $origin = 'https://auth.example.com';

        yield 'an empty id' => ['', 'Example', $origin];
        yield 'an id with a scheme' => ['https://auth.example.com', 'Example', $origin];
        yield 'an id with a port' => ['auth.example.com:443', 'Example', $origin];
        yield 'an upper-case id' => ['Auth.Example.com', 'Example', $origin];
        yield 'an id with a trailing dot' => ['auth.example.com.', 'Example', $origin];
        yield 'an id with a trailing newline' => ["auth.example.com\n", 'Example', $origin];
        yield 'an empty name' => ['auth.example.com', '', $origin];
        yield 'a name that is too long' => ['auth.example.com', str_repeat('a', 65), $origin];
        yield 'a name with a newline' => ['auth.example.com', "Exa\nmple", $origin];
        yield 'an http origin' => ['auth.example.com', 'Example', 'http://auth.example.com'];
        yield 'an origin with a path' => ['auth.example.com', 'Example', 'https://auth.example.com/auth'];
        yield 'an origin with a query' => ['auth.example.com', 'Example', 'https://auth.example.com?x=1'];
        yield 'an origin with a fragment' => ['auth.example.com', 'Example', 'https://auth.example.com#x'];
        yield 'an origin with credentials' => ['auth.example.com', 'Example', 'https://user@auth.example.com'];
        yield 'an upper-case origin' => ['auth.example.com', 'Example', 'https://AUTH.example.com'];
        yield 'an origin with a trailing slash' => ['auth.example.com', 'Example', 'https://auth.example.com/'];
        yield 'an origin that is not a URL' => ['auth.example.com', 'Example', 'auth.example.com'];
        yield 'an origin of another site' => ['auth.example.com', 'Example', 'https://auth.evil.example'];
        yield 'an origin that only ends like the id' => ['example.com', 'Example', 'https://evilexample.com'];
        yield 'an origin above the id' => ['auth.example.com', 'Example', 'https://example.com'];
    }
}
