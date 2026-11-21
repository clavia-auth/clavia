<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication;

use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignOut;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SignOutTest extends TestCase
{
    private Sessions $sessions;
    private SignOut $signOut;

    #[\Override]
    protected function setUp(): void
    {
        $clock = new FrozenClock();
        $this->sessions = new Sessions(
            new InMemorySessionStore($clock),
            new SecretGenerator(new SeededRandomSource(1)),
            $clock,
            28800,
            604800,
        );
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public('spa', ['https://app.example/cb', 'http://localhost:3000/callback']));
        $this->signOut = new SignOut($this->sessions, $clients);
    }

    public function testTheSessionIsEnded(): void
    {
        $sessionId = $this->sessions->establish(
            UserId::generate(new SeededRandomSource(2)),
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );

        $target = ($this->signOut)($sessionId, null);

        self::assertSame('/auth/login', $target);
        self::assertNull($this->sessions->resolve($sessionId));
    }

    public function testSigningOutWithoutASessionIsNotAnError(): void
    {
        self::assertSame('/auth/login', ($this->signOut)(null, null));
        self::assertSame('/auth/login', ($this->signOut)('never-issued', ''));
    }

    public function testAnHttpsAddressOnARegisteredOriginIsFollowed(): void
    {
        $next = 'https://app.example/signed-out?x=1';

        self::assertSame($next, ($this->signOut)(null, $next));
    }

    #[DataProvider('untrusted')]
    public function testAnyOtherAddressFallsBackToTheLoginPage(string $next): void
    {
        self::assertSame('/auth/login', ($this->signOut)(null, $next));
    }

    /** @return iterable<string, array{string}> */
    public static function untrusted(): iterable
    {
        yield 'an unregistered origin' => ['https://evil.example/'];
        yield 'a lookalike subdomain' => ['https://app.example.evil.example/'];
        yield 'another port' => ['https://app.example:8443/'];
        // Registered, but not over https: a sign-out redirect is not where to downgrade.
        yield 'a registered plain-http origin' => ['http://localhost:3000/'];
        yield 'plain http on a registered https host' => ['http://app.example/'];
        yield 'a relative path' => ['/elsewhere'];
        yield 'a script URL' => ['javascript:alert(1)'];
        yield 'not a URL' => ['not a url'];
        yield 'a fragment' => ['https://app.example/#x'];
    }
}
