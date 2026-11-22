<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Http\Auth\AccountPages;
use Clavia\Adapter\Primary\Http\Auth\AuthPageResponder;
use Clavia\Adapter\Primary\Http\Auth\ConsentPages;
use Clavia\Adapter\Primary\Http\Auth\LoginPages;
use Clavia\Adapter\Primary\Http\Auth\MfaPages;
use Clavia\Adapter\Primary\Http\Auth\PasskeyPages;
use Clavia\Adapter\Primary\Http\Auth\PasswordlessPages;
use Clavia\Adapter\Primary\Http\Oidc\EndSessionHandler;
use Clavia\Adapter\Primary\Http\Shared\ErrorPage;
use Clavia\Adapter\Primary\Http\Shared\HtmlPage;
use Clavia\Application\Authentication\External\ExternalProviderOption;
use Clavia\Application\Authentication\LoginPage\SignInMethods;
use Clavia\Application\Authentication\Mfa\MfaStatus;
use Clavia\Application\Authentication\Mfa\SecondFactorPage;
use Clavia\Application\Authentication\Mfa\TotpEnrollment;
use Clavia\Application\Authentication\Passkey\AccountPasskeys;
use Clavia\Application\Authentication\Passkey\AssertionOptions;
use Clavia\Application\Authentication\Passkey\DescribedPasskey;
use Clavia\Application\Authentication\Passkey\RegistrationOptions;
use Clavia\Application\Authentication\Passwordless\PasswordlessPrompt;
use Clavia\Application\OAuth2\Consent\ConsentedApi;
use Clavia\Application\OAuth2\Consent\ConsentScreen;
use Clavia\Application\OAuth2\Consent\ScopeLine;
use Clavia\Application\Oidc\Logout\SignOutConfirmationNeeded;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
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

        // A page may load this server's own module; it never prints the hostile one.
        self::assertStringNotContainsString('<script>alert', $html);
        self::assertStringNotContainsString('<img src=x', $html);
        self::assertStringNotContainsString('"\'>', $html);
        self::assertStringContainsString('&lt;script&gt;', $html);
    }

    /** @return iterable<string, array{HtmlPage}> */
    public static function pages(): iterable
    {
        yield 'the form: state, email and error' => [
            LoginPages::form(
                self::HOSTILE,
                [],
                new SignInMethods(true, true, [new ExternalProviderOption(self::HOSTILE, self::HOSTILE)], true, true),
                self::HOSTILE,
                self::HOSTILE,
                401,
            ),
        ];
        yield 'the signed-in page' => [LoginPages::signedIn(self::HOSTILE)];
        yield 'the layout: title, heading and return address' => [new HtmlPage(
            template: 'auth::login',
            title: self::HOSTILE,
            heading: self::HOSTILE,
            returnTo: self::HOSTILE,
            variables: [
                'loginState' => '',
                'email' => '',
                'signedInAs' => null,
                'password' => true,
                'emailSignIn' => false,
                'providers' => [],
                'signUpHref' => '',
                'forgotHref' => '',
                'passkeyOptions' => null,
            ],
            error: self::HOSTILE,
        )];
        yield 'the form with a passkey: state, email, error and options' => [LoginPages::form(
            self::HOSTILE,
            [],
            new SignInMethods(true, false, [], false, false, true),
            self::HOSTILE,
            self::HOSTILE,
            401,
            new AssertionOptions(
                self::HOSTILE,
                RelyingParty::of('auth.clavia.test', 'Clavia', 'https://auth.clavia.test'),
                WebAuthnChallenge::forSignIn(
                    new SeededRandomSource(1),
                    self::HOSTILE,
                    new DateTimeImmutable('2026-01-15T10:00:00Z'),
                    300,
                ),
                [],
                300,
            ),
        )];
        yield 'the sign-up form: state, address and error' => [
            AccountPages::signUp(self::HOSTILE, [], true, self::HOSTILE, self::HOSTILE, 400),
        ];
        yield 'check your inbox: address and handle' => [
            AccountPages::checkInbox(self::HOSTILE, 'sign-up', self::HOSTILE),
        ];
        yield 'check your inbox after a reset request' => [AccountPages::checkInbox(self::HOSTILE, 'reset', null)];
        yield 'check your inbox for an unverified account' => [
            AccountPages::checkInbox(self::HOSTILE, 'unverified', null),
        ];
        yield 'the verification link: address, token and error' => [
            AccountPages::confirmEmail(self::HOSTILE, self::HOSTILE, self::HOSTILE, 400),
        ];
        yield 'the confirmed address: address and handle' => [
            AccountPages::emailVerified(self::HOSTILE, self::HOSTILE),
        ];
        yield 'the forgot form: state, address and error' => [
            AccountPages::forgot(self::HOSTILE, self::HOSTILE, self::HOSTILE, 400),
        ];
        yield 'the reset form: address, token and error' => [
            AccountPages::resetForm(self::HOSTILE, self::HOSTILE, self::HOSTILE, 400),
        ];
        yield 'the changed password: address and handle' => [
            AccountPages::passwordChanged(self::HOSTILE, self::HOSTILE),
        ];
        yield 'the second step: error' => [
            MfaPages::challenge(new SecondFactorPage([], true, false), null, self::HOSTILE, 401),
        ];
        yield 'the second step with a passkey: error and options' => [MfaPages::challenge(
            new SecondFactorPage([], false, true),
            new AssertionOptions(
                self::HOSTILE,
                RelyingParty::of('auth.clavia.test', 'Clavia', 'https://auth.clavia.test'),
                WebAuthnChallenge::forSecondFactor(
                    new SeededRandomSource(1),
                    UserId::generate(new SeededRandomSource(2)),
                    self::HOSTILE,
                    new DateTimeImmutable('2026-01-15T10:00:00Z'),
                    300,
                ),
                [],
                300,
            ),
            self::HOSTILE,
            401,
        )];
        yield 'the code page: address and error' => [
            PasswordlessPages::code(new PasswordlessPrompt(self::HOSTILE, []), self::HOSTILE, 401),
        ];
        yield 'the link sent: address' => [PasswordlessPages::linkSent(self::HOSTILE)];
        yield 'the link confirmation: address, token and error' => [
            PasswordlessPages::linkConfirm(
                new PasswordlessPrompt(self::HOSTILE, []),
                self::HOSTILE,
                self::HOSTILE,
                400,
            ),
        ];
        yield 'the consent screen: application, account, scopes, API and handle' => [ConsentPages::question(
            new ConsentScreen(
                self::HOSTILE,
                self::HOSTILE,
                [new ScopeLine(self::HOSTILE, self::HOSTILE)],
                new ConsentedApi(self::HOSTILE, self::HOSTILE, [new ScopeLine(self::HOSTILE, self::HOSTILE)]),
                [],
            ),
            self::HOSTILE,
            self::HOSTILE,
            400,
        )];
        yield 'the expired consent screen' => [new HtmlPage(
            template: 'auth::consent-expired',
            title: self::HOSTILE,
            heading: self::HOSTILE,
            error: self::HOSTILE,
        )];
        yield 'the two-factor settings: email' => [MfaPages::settings(new MfaStatus(self::HOSTILE, true, 3, 2))];
        yield 'the two-factor settings, off: email' => [MfaPages::settings(new MfaStatus(self::HOSTILE, false, 0))];
        yield 'the set-up page: seed and error' => [
            MfaPages::setUp(
                new TotpEnrollment(self::HOSTILE, 'otpauth://totp/' . rawurlencode(self::HOSTILE)),
                self::HOSTILE,
            ),
        ];
        yield 'the recovery codes' => [MfaPages::recoveryCodes([self::HOSTILE, 'abcd-efgh-jkmn'])];
        yield 'the passkeys: address, names and ids' => [PasskeyPages::list(
            new AccountPasskeys(
                self::HOSTILE,
                [new DescribedPasskey(
                    self::HOSTILE,
                    self::HOSTILE,
                    true,
                    new DateTimeImmutable('2026-01-15T10:00:00Z'),
                    new DateTimeImmutable('2026-01-16T10:00:00Z'),
                )],
                10,
            ),
            self::HOSTILE,
            400,
        )];
        yield 'the page that makes a passkey: address, names and options' => [PasskeyPages::create(
            new RegistrationOptions(
                self::HOSTILE,
                RelyingParty::of('auth.clavia.test', 'Clavia', 'https://auth.clavia.test'),
                WebAuthnChallenge::forRegistration(
                    new SeededRandomSource(1),
                    UserId::generate(new SeededRandomSource(2)),
                    new DateTimeImmutable('2026-01-15T10:00:00Z'),
                    300,
                ),
                self::HOSTILE,
                self::HOSTILE,
                [],
                300,
            ),
            self::HOSTILE,
        )];
        yield 'the recovery codes of a first passkey' => [PasskeyPages::recoveryCodes([self::HOSTILE, 'abcd-efgh'])];
        yield 'the sign-out confirmation: client name and carried fields' => [
            EndSessionHandler::confirmation(new SignOutConfirmationNeeded(
                self::HOSTILE,
                self::HOSTILE,
                'https://app.example/' . self::HOSTILE,
                self::HOSTILE,
            )),
        ];
        yield 'an error page: message, advice and reference' => [
            new ErrorPage(self::HOSTILE, self::HOSTILE, self::HOSTILE, self::HOSTILE)->toHtmlPage(400),
        ];
    }
}
