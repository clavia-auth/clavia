<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http;

use Clavia\Adapter\Primary\Http\Auth\AuthCookies;
use Clavia\Adapter\Primary\Http\Auth\CsrfToken;
use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Clavia\Adapter\Primary\Http\Shared\SetCookie;
use InvalidArgumentException;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CookiesTest extends TestCase
{
    // ── Set-Cookie ─────────────────────────────────────────────────────────────

    public function testACookieIsHostOnlyHttpOnlyAndLax(): void
    {
        $header = SetCookie::create('clavia_session', 'abc-DEF_123', 604800, '/', true)->toString();

        self::assertSame(
            'clavia_session=abc-DEF_123; Max-Age=604800; Path=/; Secure; HttpOnly; SameSite=Lax',
            $header,
        );
        self::assertStringNotContainsStringIgnoringCase('domain', $header);
    }

    public function testSecureIsLeftOutOnlyWhenAsked(): void
    {
        self::assertSame(
            'clavia_csrf=t; Max-Age=3600; Path=/auth; HttpOnly; SameSite=Lax',
            SetCookie::create('clavia_csrf', 't', 3600, '/auth', false)->toString(),
        );
    }

    public function testExpiringACookieWorksForOldBrowsersToo(): void
    {
        self::assertSame(
            'clavia_csrf=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; '
            . 'Path=/auth; Secure; HttpOnly; SameSite=Lax',
            SetCookie::expire('clavia_csrf', '/auth', true)->toString(),
        );
    }

    #[DataProvider('injections')]
    /**
     * @param non-empty-string $name
     */
    public function testNothingCanBreakOutOfTheHeader(string $name, string $value): void
    {
        $this->expectException(InvalidArgumentException::class);

        SetCookie::create($name, $value, 60, '/', true);
    }

    /** @return iterable<string, array{non-empty-string, string}> */
    public static function injections(): iterable
    {
        yield 'a semicolon in the value' => ['a', 'x; Domain=evil.example'];
        yield 'a line break in the value' => ['a', "x\r\nSet-Cookie: b=c"];
        yield 'a space in the value' => ['a', 'x y'];
        yield 'a quote in the value' => ['a', 'x"'];
        yield 'an equals sign in the name' => ['a=b', 'x'];
    }

    public function testTheAuthCookiesAreDeletedWithThePathsTheyWereSetWith(): void
    {
        $cookies = new AuthCookies('clavia_session', 604800, true);

        self::assertStringContainsString('Path=/;', $cookies->session('s')->toString());
        self::assertStringContainsString('Path=/;', $cookies->expireSession()->toString());
        self::assertStringContainsString('Path=/auth;', $cookies->csrf('t')->toString());
        self::assertStringContainsString('Path=/auth;', $cookies->expireCsrf()->toString());
        self::assertStringContainsString('Path=/;', $cookies->expireStrayCsrf()->toString());
        self::assertStringContainsString('Path=/;', $cookies->theme('dark')->toString());
        self::assertStringContainsString('Path=/;', $cookies->expireTheme()->toString());
        self::assertStringContainsString('Path=/auth;', $cookies->mfaChallenge('c')->toString());
        self::assertStringContainsString('Path=/auth;', $cookies->expireMfaChallenge()->toString());
        self::assertStringContainsString('Path=/auth;', $cookies->passwordless('p')->toString());
        self::assertStringContainsString('Path=/auth;', $cookies->expirePasswordless()->toString());
    }

    public function testTheChallengeCookieLivesAsLongAsTheChallengeAndNoLonger(): void
    {
        $cookie = new AuthCookies('clavia_session', 604800, true, 120)->mfaChallenge('handle')->toString();

        self::assertStringStartsWith('clavia_mfa=handle;', $cookie);
        self::assertStringContainsString('Max-Age=120;', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie);
        self::assertStringContainsString('Secure', $cookie);
        self::assertStringContainsString('SameSite=Lax', $cookie);
    }

    public function testThePasswordlessCookieLivesAsLongAsTheCode(): void
    {
        $cookie = new AuthCookies('clavia_session', 604800, true, 120, 480)->passwordless('handle')->toString();

        self::assertStringStartsWith('clavia_passwordless=handle;', $cookie);
        self::assertStringContainsString('Max-Age=480;', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie);
        self::assertStringContainsString('SameSite=Lax', $cookie);
    }

    // ── Cookie ──────────────────────────────────────────────────────────────────

    public function testEveryValueOfANameIsReadInTheOrderSent(): void
    {
        $request = $this->request('clavia_csrf=current; other=x; clavia_csrf=stale');

        self::assertSame(['current', 'stale'], RequestCookies::all($request, 'clavia_csrf'));
        self::assertSame('current', RequestCookies::first($request, 'clavia_csrf'));
        self::assertSame('x', RequestCookies::first($request, 'other'));
    }

    public function testNamesAreNotRewrittenAndEmptyValuesCarryNothing(): void
    {
        $request = $this->request('a.b=1; a_c=; broken; =orphan; spaced = v ');

        self::assertSame('1', RequestCookies::first($request, 'a.b'));
        self::assertNull(RequestCookies::first($request, 'a_b'));
        self::assertNull(RequestCookies::first($request, 'a_c'));
        self::assertNull(RequestCookies::first($request, 'broken'));
        self::assertSame('v', RequestCookies::first($request, 'spaced'));
        self::assertSame([], RequestCookies::all(new ServerRequest(), 'a'));
    }

    // ── CSRF ────────────────────────────────────────────────────────────────────

    public function testTheSubmittedTokenMustEqualOneTheBrowserHolds(): void
    {
        $request = $this->request('clavia_csrf=current; clavia_csrf=stale');

        self::assertTrue(CsrfToken::isValid($request, 'current'));
        self::assertTrue(CsrfToken::isValid($request, 'stale'));
        self::assertFalse(CsrfToken::isValid($request, 'forged'));
        self::assertFalse(CsrfToken::isValid($request, 'curren'));
        self::assertFalse(CsrfToken::isValid($request, ''));
        self::assertFalse(CsrfToken::isValid($request, null));
    }

    public function testWithoutACookieNoTokenIsValid(): void
    {
        self::assertFalse(CsrfToken::isValid(new ServerRequest(), 'anything'));
        self::assertFalse(CsrfToken::isValid($this->request('clavia_csrf='), ''));
    }

    private function request(string $cookie): ServerRequest
    {
        return new ServerRequest(headers: ['Cookie' => $cookie]);
    }
}
