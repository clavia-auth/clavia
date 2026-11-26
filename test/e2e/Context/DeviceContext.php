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
 * The device authorization grant (RFC 8628) as a television and a phone live it: the device asks for a
 * code and polls at the interval it was given (§3.5); the person signs in through the real login page,
 * types nothing (the address carries the code, `verification_uri_complete`), and decides on the review
 * page.
 *
 * @psalm-suppress MissingConstructor The scenario's hook gathers what this context shares, before any step.
 */
final class DeviceContext implements Context
{
    private const string GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

    private Browser $browser;
    private ManagementContext $management;
    /** @var array<string, mixed> */
    private array $authorization = [];
    private float $lastPoll = 0.0;
    private ?ResponseInterface $poll = null;

    #[BeforeScenario]
    public function gather(BeforeScenarioScope $scope): void
    {
        $this->browser = Contexts::of($scope, HttpContext::class)->browser();
        $this->management = Contexts::of($scope, ManagementContext::class);
    }

    #[When('the device asks for a code, asking for :scope')]
    public function theDeviceAsksForACode(string $scope): void
    {
        $response = $this->browser->request(
            RequestMethodInterface::METHOD_POST,
            $this->browser->stack()->authUrl('/oauth2/device/code'),
            ['form_params' => ['client_id' => $this->management->application()->clientId, 'scope' => $scope]],
        );
        Check::same(200, $response->getStatusCode(), (string) $response->getBody());
        Check::includes('no-store', $response->getHeaderLine('Cache-Control'));
        $this->authorization = self::json($response);
    }

    #[Then('it is told where to go, which code to type and how often to ask')]
    public function itIsToldWhereToGo(): void
    {
        $stack = $this->browser->stack();
        Check::same($stack->authUrl('/auth/device'), $this->authorization['verification_uri'] ?? null);
        Check::string($this->authorization['user_code'] ?? null, 'a user code');
        // UserCode::ALPHABET: no vowel, so no word; grouped in fours, as a person types it.
        Check::matches(
            '/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/D',
            (string) $this->authorization['user_code'],
        );
        $complete = (string) ($this->authorization['verification_uri_complete'] ?? '');
        Check::startsWith($stack->authUrl('/auth/device?'), $complete);
        /** @var mixed $interval */
        $interval = $this->authorization['interval'] ?? null;
        Check::that(is_int($interval) && $interval >= 5, 'an interval of at least five seconds');
    }

    #[Then('asking for its tokens now, it is told to wait')]
    public function askingNowItIsToldToWait(): void
    {
        $response = $this->poll();
        Check::same(400, $response->getStatusCode(), (string) $response->getBody());
        Check::same('authorization_pending', self::json($response)['error'] ?? null);
    }

    #[When('the person approves the code from their browser')]
    public function thePersonApproves(): void
    {
        $this->decide('allow');
    }

    #[When('the person refuses the code from their browser')]
    public function thePersonRefuses(): void
    {
        $this->decide('deny');
    }

    #[When('the device asks for its tokens again, at the pace it was given')]
    public function theDeviceAsksAgain(): void
    {
        // RFC 8628 §3.5: asking sooner than the interval is `slow_down`, which this scenario is not about.
        $interval = (int) ($this->authorization['interval'] ?? 5);
        $wait = $this->lastPoll + (float) ($interval + 1) - microtime(true);
        if ($wait > 0.0) {
            usleep((int) ($wait * 1_000_000.0));
        }
        $this->poll = $this->poll();
    }

    #[Then('it is given an access token and an ID token')]
    public function itIsGivenTokens(): void
    {
        $response = $this->poll ?? throw new \LogicException('The device has not asked again.');
        Check::same(200, $response->getStatusCode(), (string) $response->getBody());
        $tokens = self::json($response);
        Check::string($tokens['access_token'] ?? null, 'an access token');
        Check::string($tokens['id_token'] ?? null, 'an ID token');
        Check::same('Bearer', $tokens['token_type'] ?? null);
    }

    #[Then('it is told the person refused')]
    public function itIsToldThePersonRefused(): void
    {
        $response = $this->poll ?? throw new \LogicException('The device has not asked again.');
        Check::same(400, $response->getStatusCode(), (string) $response->getBody());
        Check::same('access_denied', self::json($response)['error'] ?? null);
    }

    /**
     * Open the address the device showed, sign in through the login page it leads to, and press one of
     * the review page's two buttons.
     */
    private function decide(string $decision): void
    {
        $person = $this->management->person();
        $stack = $this->browser->stack();
        $this->browser->request(
            RequestMethodInterface::METHOD_GET,
            (string) ($this->authorization['verification_uri_complete'] ?? ''),
        );
        $login = $this->browser->follow(static fn (string $target): bool => false);
        $html = (string) $login->getBody();
        Check::same(1, preg_match('/name="csrf_token" value="([^"]+)"/', $html, $csrf), 'no login form');
        preg_match('/name="state" value="([^"]*)"/', $html, $state);
        $this->browser->request(RequestMethodInterface::METHOD_POST, $stack->authUrl('/auth/login'), [
            'form_params' => [
                'email' => $person->email,
                'password' => $person->password,
                'csrf_token' => html_entity_decode($csrf[1]),
                'state' => html_entity_decode($state[1] ?? ''),
            ],
        ]);

        // Signed in, back at the review page for the code the address carried.
        $review = $this->browser->follow(static fn (string $target): bool => false);
        Check::same(200, $review->getStatusCode(), substr((string) $review->getBody(), 0, 300));
        $html = (string) $review->getBody();
        Check::same(1, preg_match('/name="decision" value="allow"/', $html), 'no review page');
        Check::same(1, preg_match('/name="csrf_token" value="([^"]+)"/', $html, $csrf), 'no CSRF token');
        $decided = $this->browser->request(RequestMethodInterface::METHOD_POST, $stack->authUrl('/auth/device'), [
            'form_params' => [
                'user_code' => (string) ($this->authorization['user_code'] ?? ''),
                'decision' => $decision,
                'csrf_token' => html_entity_decode($csrf[1]),
            ],
        ]);
        Check::same(200, $decided->getStatusCode(), substr((string) $decided->getBody(), 0, 300));
    }

    private function poll(): ResponseInterface
    {
        $this->lastPoll = microtime(true);

        return $this->browser->request(
            RequestMethodInterface::METHOD_POST,
            $this->browser->stack()->authUrl('/oauth2/token'),
            ['form_params' => [
                'grant_type' => self::GRANT,
                'device_code' => (string) ($this->authorization['device_code'] ?? ''),
                'client_id' => $this->management->application()->clientId,
            ]],
        );
    }

    /** @return array<string, mixed> */
    private static function json(ResponseInterface $response): array
    {
        /** @var array<string, mixed> */
        return json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
    }
}
