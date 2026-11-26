<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\E2e\Context;

use Behat\Behat\Context\Context;
use Behat\Behat\Hook\Scope\BeforeScenarioScope;
use Behat\Hook\BeforeScenario;
use Behat\Step\Then;
use Behat\Step\When;
use Fig\Http\Message\RequestMethodInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * The pages of an account, as a person uses them from a mail or the sign-in page: signing up, confirming
 * an address, asking for a new password and choosing one. Each is a form with a CSRF token, posted as a
 * browser posts it.
 */
/**
 * @psalm-suppress MissingConstructor The scenario's hook gathers what this context shares, before any step.
 */
final class AccountContext implements Context
{
    private Browser $browser;
    private ManagementContext $management;
    private SignInContext $signIn;
    private MailContext $mail;

    private ?ResponseInterface $answer = null;
    private string $chosenPassword = '';
    private string $csrfToken = '';

    #[BeforeScenario]
    public function gather(BeforeScenarioScope $scope): void
    {
        $this->browser = Contexts::of($scope, HttpContext::class)->browser();
        $this->management = Contexts::of($scope, ManagementContext::class);
        $this->signIn = Contexts::of($scope, SignInContext::class);
        $this->mail = Contexts::of($scope, MailContext::class);
    }

    #[When('the visitor signs up at the application with that address and password')]
    public function theVisitorSignsUp(): void
    {
        $page = $this->signIn->loginPage('openid');
        $person = $this->management->person();

        $this->answer = $this->post('/auth/signup', [
            'email' => $person->email,
            'password' => $person->password,
            'csrf_token' => $page->csrfToken,
            'state' => $page->handle,
        ]);
    }

    #[Then('they are asked to check their email, and nobody is signed in')]
    public function theyAreAskedToCheckTheirEmail(): void
    {
        $answer = $this->answer();
        Check::same(200, $answer->getStatusCode(), (string) $answer->getBody());
        Check::includes('Check your email', (string) $answer->getBody());
        Check::that(! $answer->hasHeader('Location'), 'the sign-up signed the visitor in');
    }

    #[When('the link is opened twice, as a mail scanner would')]
    public function theLinkIsOpenedTwice(): void
    {
        for ($time = 1; $time <= 2; ++$time) {
            $page = $this->browser->request(RequestMethodInterface::METHOD_GET, $this->mail->link());
            Check::same(200, $page->getStatusCode(), 'opening the link, time ' . $time);
        }
    }

    #[Then('the page still asks them to confirm')]
    public function thePageStillAsksThemToConfirm(): void
    {
        $page = $this->browser->request(RequestMethodInterface::METHOD_GET, $this->mail->link());
        Check::includes('Confirm my address', (string) $page->getBody());
    }

    #[When('they confirm their address')]
    public function theyConfirmTheirAddress(): void
    {
        $this->answer = $this->postFromLink('/auth/verify-email', []);
    }

    #[Then('the address is confirmed, and nobody is signed in')]
    public function theAddressIsConfirmed(): void
    {
        $answer = $this->answer();
        Check::same(200, $answer->getStatusCode(), (string) $answer->getBody());
        Check::includes('is confirmed', (string) $answer->getBody());
        Check::that(! $answer->hasHeader('Location'), 'confirming an address signed the visitor in');
    }

    #[Then('confirming with the same link again is refused')]
    public function confirmingAgainIsRefused(): void
    {
        $this->theSpentLinkIsRefused('/auth/verify-email', []);
    }

    #[Then('they can sign in with that address and password')]
    public function theyCanSignIn(): void
    {
        $person = $this->management->person();
        $this->signInWith($person->password);
    }

    #[When('the person asks for a new password')]
    public function thePersonAsksForANewPassword(): void
    {
        $form = $this->browser->request(
            RequestMethodInterface::METHOD_GET,
            $this->browser->stack()->authUrl('/auth/password/forgot'),
        );
        $this->answer = $this->post('/auth/password/forgot', [
            'email' => $this->management->person()->email,
            'csrf_token' => self::csrfTokenIn($form),
            'state' => '',
        ]);
        Check::same(200, $this->answer->getStatusCode(), (string) $this->answer->getBody());
    }

    #[When('the person chooses the password :password from the link')]
    public function thePersonChoosesAPassword(string $password): void
    {
        $this->answer = $this->postFromLink('/auth/password/reset', ['password' => $password]);
        $this->chosenPassword = $password;
    }

    #[Then('the password is changed')]
    public function thePasswordIsChanged(): void
    {
        $answer = $this->answer();
        Check::same(200, $answer->getStatusCode(), (string) $answer->getBody());
        Check::includes('Password changed', (string) $answer->getBody());
    }

    #[Then('choosing a password with the same link again is refused')]
    public function choosingAgainIsRefused(): void
    {
        $this->theSpentLinkIsRefused('/auth/password/reset', ['password' => 'another passphrase 2']);
    }

    #[Then('the chosen password signs them in')]
    public function theChosenPasswordSignsThemIn(): void
    {
        $this->signInWith($this->chosenPassword);
    }

    #[Then('the old password no longer signs them in')]
    public function theOldPasswordNoLongerSignsThemIn(): void
    {
        $page = $this->signIn->loginPage('openid');
        $person = $this->management->person();

        $refused = $this->signIn->postLogin($page, $person->email, $person->password);
        Check::same(401, $refused->getStatusCode(), (string) $refused->getBody());
    }

    private function signInWith(string $password): void
    {
        $page = $this->signIn->loginPage('openid');
        $answer = $this->signIn->postLogin($page, $this->management->person()->email, $password);
        Check::same(303, $answer->getStatusCode(), 'signing in: ' . substr((string) $answer->getBody(), 0, 300));
        $this->signIn->landAtTheApplication();
    }

    /**
     * A spent link is dead twice over: its page is refused, and so is the form posted from the page as it
     * was before (the CSRF token is the browser's, and still good).
     *
     * @param array<string, string> $fields
     */
    private function theSpentLinkIsRefused(string $path, array $fields): void
    {
        $page = $this->browser->request(RequestMethodInterface::METHOD_GET, $this->mail->link());
        Check::same(400, $page->getStatusCode(), 'the page of a spent link: ' . self::start($page));

        $again = $this->post($path, ['token' => $this->tokenOfTheLink(), 'csrf_token' => $this->csrfToken] + $fields);
        Check::same(400, $again->getStatusCode(), 'posting from a spent link: ' . self::start($again));
    }

    private function tokenOfTheLink(): string
    {
        parse_str((string) parse_url($this->mail->link(), PHP_URL_QUERY), $query);
        $token = $query['token'] ?? null;
        Check::string($token, 'a token in the link');

        return $token;
    }

    /**
     * Open the link, then post the form on the page it opens, with the link's token.
     *
     * @param array<string, string> $fields
     */
    private function postFromLink(string $path, array $fields): ResponseInterface
    {
        $page = $this->browser->request(RequestMethodInterface::METHOD_GET, $this->mail->link());
        $this->csrfToken = self::csrfTokenIn($page);

        return $this->post($path, ['token' => $this->tokenOfTheLink(), 'csrf_token' => $this->csrfToken] + $fields);
    }

    /** @param array<string, string> $form */
    private function post(string $path, array $form): ResponseInterface
    {
        return $this->browser->request(
            RequestMethodInterface::METHOD_POST,
            $this->browser->stack()->authUrl($path),
            ['form_params' => $form],
        );
    }

    private function answer(): ResponseInterface
    {
        return $this->answer ?? throw new \LogicException('Nothing was answered yet.');
    }

    private static function start(ResponseInterface $response): string
    {
        return substr((string) $response->getBody(), 0, 300);
    }

    private static function csrfTokenIn(ResponseInterface $page): string
    {
        $body = (string) $page->getBody();
        Check::same(
            1,
            preg_match('/name="csrf_token" value="([^"]+)"/', $body, $match),
            'no CSRF token on ' . $page->getStatusCode() . ': ' . self::start($page),
        );

        return $match[1];
    }
}
