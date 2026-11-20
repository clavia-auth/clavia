<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Http\Auth\AuthPageResponder;
use Clavia\Adapter\Primary\Http\Auth\LoginPages;
use Clavia\Adapter\Primary\Http\Auth\MfaPages;
use Clavia\Adapter\Primary\Http\Shared\ErrorPage;
use Clavia\Adapter\Primary\Http\Shared\HtmlPage;
use Clavia\Application\Authentication\Mfa\MfaStatus;
use Clavia\Application\Authentication\Mfa\TotpEnrollment;
use ClaviaTest\Support\AcceptanceTestCase;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Every value a page prints is escaped for where it is printed.
 *
 * laminas-view does not escape by itself; the templates call `escapeHtml()` or
 * `escapeHtmlAttr()` on each value. This renders every page through the real renderer
 * with values built to break out of an element or an attribute, so a template that
 * forgets fails here.
 */
final class AuthPagesEscapingTest extends AcceptanceTestCase
{
    private const string HOSTILE = '"\'><script>alert(1)</script><img src=x onerror=alert(2)>';

    #[DataProvider('pages')]
    public function testAHostileValueIsNeverPrintedAsMarkup(HtmlPage $page): void
    {
        /** @var AuthPageResponder $responder */
        $responder = $this->container()->get(AuthPageResponder::class);

        $html = (string) $responder->page(new ServerRequest(), $page)->getBody();

        self::assertStringNotContainsString('<script', $html);
        self::assertStringNotContainsString('<img src=x', $html);
        self::assertStringNotContainsString('"\'>', $html);
        self::assertStringContainsString('&lt;script&gt;', $html);
    }

    /** @return iterable<string, array{HtmlPage}> */
    public static function pages(): iterable
    {
        yield 'the form: state, email and error' => [
            LoginPages::form(self::HOSTILE, [], self::HOSTILE, self::HOSTILE, 401),
        ];
        yield 'the signed-in page' => [LoginPages::signedIn(self::HOSTILE)];
        yield 'the layout: title, heading and return address' => [new HtmlPage(
            template: 'auth::login',
            title: self::HOSTILE,
            heading: self::HOSTILE,
            returnTo: self::HOSTILE,
            variables: ['loginState' => '', 'email' => '', 'signedInAs' => null],
            error: self::HOSTILE,
        )];
        yield 'the second step: error' => [MfaPages::challenge([], self::HOSTILE, 401)];
        yield 'the two-factor settings: email' => [MfaPages::settings(new MfaStatus(self::HOSTILE, true, 3))];
        yield 'the two-factor settings, off: email' => [MfaPages::settings(new MfaStatus(self::HOSTILE, false, 0))];
        yield 'the set-up page: seed and error' => [
            MfaPages::setUp(
                new TotpEnrollment(self::HOSTILE, 'otpauth://totp/' . rawurlencode(self::HOSTILE)),
                self::HOSTILE,
            ),
        ];
        yield 'the recovery codes' => [MfaPages::recoveryCodes([self::HOSTILE, 'abcd-efgh-jkmn'])];
        yield 'an error page: message, advice and reference' => [
            new ErrorPage(self::HOSTILE, self::HOSTILE, self::HOSTILE, self::HOSTILE)->toHtmlPage(400),
        ];
    }
}
