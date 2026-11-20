<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External;

use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Application\Port\IdentityProviderFailed;
use Clavia\Application\Port\IdentityProviders;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Identity\User;

/**
 * Finish a sign-in at the provider's redirect.
 *
 * Both `state` values must agree — the one the provider echoed and the one the browser
 * was given when the sign-in started — before the store is touched: the store alone
 * proves *a* sign-in was started; the cookie proves this browser started it, which is
 * what stops an attacker completing their own sign-in inside a victim's browser (login
 * CSRF, RFC 6749 §10.12). The pending sign-in is then claimed, so a `state` works once.
 *
 * What follows is the same as after a password: {@see CompleteFirstFactor}, so an
 * account with a second factor gets its challenge — signing in with a provider is not a
 * way around it.
 */
final readonly class CompleteExternalSignIn
{
    public function __construct(
        private IdentityProviders $providers,
        private ExternalSignInStore $pending,
        private ResolveExternalAccount $resolveAccount,
        private LoginStateStore $loginStates,
        private CompleteFirstFactor $completeFirstFactor,
        private string $issuer,
    ) {
    }

    /**
     * @return SignedIn|SecondFactorRequired|ExternalSignInRefused|null Null when no configured
     *                                                                  provider has that name.
     */
    public function __invoke(ExternalCallback $callback): SignedIn|SecondFactorRequired|ExternalSignInRefused|null
    {
        $provider = $this->providers->find($callback->provider);
        if ($provider === null) {
            return null;
        }
        $refuse = static fn (ExternalSignInFailure $reason): ExternalSignInRefused
            => new ExternalSignInRefused($reason, $provider->label());

        if ($callback->errorReported || $callback->code === null || $callback->state === null) {
            return $refuse(ExternalSignInFailure::Cancelled);
        }
        if ($callback->browserState === null || ! hash_equals($callback->browserState, $callback->state)) {
            return $refuse(ExternalSignInFailure::StartedInAnotherBrowser);
        }

        $pending = $this->pending->claim($callback->state);
        if ($pending === null || ! $pending->provider->equals($provider->name())) {
            return $refuse(ExternalSignInFailure::Expired);
        }

        try {
            $asserted = $provider->identify(
                $callback->code,
                ExternalCallbackUrl::for($this->issuer, $provider->name()),
                $pending->codeVerifier,
            );
        } catch (IdentityProviderFailed) {
            return $refuse(ExternalSignInFailure::ProviderFailed);
        }
        if (! $asserted->provider->equals($provider->name())) {
            return $refuse(ExternalSignInFailure::ProviderFailed);
        }

        $account = ($this->resolveAccount)($asserted);
        if (! $account instanceof User) {
            return $refuse($account);
        }

        // The login page's handle has done its job, as after a password.
        if ($pending->loginState !== null) {
            $this->loginStates->forget($pending->loginState);
        }

        return ($this->completeFirstFactor)(
            $account->id,
            [AuthenticationMethod::External],
            $pending->nextUrl,
            $pending->clientId,
            $callback->currentSessionId,
        );
    }
}
