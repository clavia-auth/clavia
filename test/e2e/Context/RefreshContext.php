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

/**
 * Refresh tokens as an application uses them: each is spent once, and one presented again is a theft
 * signal that takes its whole family with it (RFC 9700 §4.14.2).
 */
/**
 * @psalm-suppress MissingConstructor The scenario's hook gathers what this context shares, before any step.
 */
final class RefreshContext implements Context
{
    private Browser $browser;
    private SignInContext $signIn;
    private ManagementContext $management;

    private string $spent = '';
    private string $current = '';

    #[BeforeScenario]
    public function gather(BeforeScenarioScope $scope): void
    {
        $this->browser = Contexts::of($scope, HttpContext::class)->browser();
        $this->signIn = Contexts::of($scope, SignInContext::class);
        $this->management = Contexts::of($scope, ManagementContext::class);
    }

    #[Then('the token response carries a refresh token')]
    public function theTokenResponseCarriesARefreshToken(): void
    {
        $refresh = $this->signIn->token('refresh_token');
        Check::string($refresh, 'no refresh token in ' . (string) $this->browser->last()->getBody());
        $this->current = $refresh;
    }

    #[When('the application refreshes with it')]
    public function theApplicationRefreshesWithIt(): void
    {
        $this->spent = $this->current;
        $this->signIn->redeem($this->refreshForm($this->spent));
        Check::same(200, $this->browser->last()->getStatusCode(), (string) $this->browser->last()->getBody());
        $next = $this->signIn->token('refresh_token');
        Check::string($next, 'the refresh gave no new refresh token');
        $this->current = $next;
    }

    #[Then('it is given a new refresh token and a new access token')]
    public function itIsGivenNewTokens(): void
    {
        Check::notSame($this->spent, $this->current, 'the refresh token was not rotated');
        Check::string($this->signIn->token('access_token'));
    }

    #[When('the application presents the spent refresh token again')]
    public function theApplicationPresentsTheSpentRefreshTokenAgain(): void
    {
        $this->signIn->redeem($this->refreshForm($this->spent));
    }

    #[When('the application presents the refresh token it was last given')]
    public function theApplicationPresentsTheLastRefreshToken(): void
    {
        $this->signIn->redeem($this->refreshForm($this->current));
    }

    #[Then('it is refused as an invalid grant')]
    public function itIsRefusedAsAnInvalidGrant(): void
    {
        Check::same(400, $this->browser->last()->getStatusCode(), (string) $this->browser->last()->getBody());
        Check::same('invalid_grant', $this->signIn->token('error'));
        Check::that($this->signIn->token('access_token') === null, 'an access token was issued');
        Check::that($this->signIn->token('refresh_token') === null, 'a refresh token was issued');
    }

    /** @return array<string, string> */
    private function refreshForm(string $refreshToken): array
    {
        return [
            'grant_type' => 'refresh_token',
            'client_id' => $this->management->application()->clientId,
            'refresh_token' => $refreshToken,
        ];
    }
}
