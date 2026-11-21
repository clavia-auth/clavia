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
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Application\Port\IdentityProviderFailed;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Event\SignInRefused;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Shared\InvalidValue;

/**
 * Finish a sign-in at the provider's redirect.
 *
 * Both `state` values must agree — the one the provider echoed and the one the browser
 * was given when the sign-in started — before the store is touched: the store alone
 * proves *a* sign-in was started; the cookie proves this browser started it, which is
 * what stops an attacker completing their own sign-in inside a victim's browser (login
 * CSRF, RFC 6749 §10.12). The pending sign-in is then claimed, so a `state` works once.
 *
 * The application must still let its users in through the connection, as when the
 * sign-in began. The account is looked for in the pools it may sign people in from, and
 * the session records the connection the person came through. What follows is the same
 * as after a password: {@see CompleteFirstFactor}, so an account with a second factor
 * gets its challenge — signing in with a provider is not a way around it.
 */
final readonly class CompleteExternalSignIn
{
    public function __construct(
        private ConnectionAccess $access,
        private ClientRepository $clients,
        private ExternalSignInStore $pending,
        private ResolveExternalAccount $resolveAccount,
        private LoginStateStore $loginStates,
        private CompleteFirstFactor $completeFirstFactor,
        private string $issuer,
        private DomainEvents $events,
    ) {
    }

    /**
     * @return SignedIn|SecondFactorRequired|ExternalSignInRefused|null Null when no usable external
     *                                                                  connection has that name.
     */
    public function __invoke(ExternalCallback $callback): SignedIn|SecondFactorRequired|ExternalSignInRefused|null
    {
        try {
            $usable = $this->access->external(ConnectionName::fromString($callback->provider));
        } catch (InvalidValue) {
            $usable = null;
        }
        $provider = $usable?->provider;
        if ($usable === null || $provider === null) {
            return null;
        }
        $connection = $usable->connection;
        $refuse = function (ExternalSignInFailure $reason) use ($connection): ExternalSignInRefused {
            $this->events->dispatch(new SignInRefused(
                AuthenticationMethod::External,
                $reason->refusal(),
                connection: $connection->name,
            ));

            return new ExternalSignInRefused($reason, $connection->displayName);
        };

        if ($callback->errorReported || $callback->code === null || $callback->state === null) {
            return $refuse(ExternalSignInFailure::Cancelled);
        }
        if ($callback->browserState === null || ! hash_equals($callback->browserState, $callback->state)) {
            return $refuse(ExternalSignInFailure::StartedInAnotherBrowser);
        }

        $pending = $this->pending->claim($callback->state);
        if ($pending === null || ! $pending->provider->equals($connection->name)) {
            return $refuse(ExternalSignInFailure::Expired);
        }

        $client = $pending->clientId === null ? null : $this->clients->find($pending->clientId);
        if (! $this->access->allows($client, $connection->name)) {
            return $refuse(ExternalSignInFailure::NotAvailable);
        }

        try {
            $asserted = $provider->identify(
                $callback->code,
                ExternalCallbackUrl::for($this->issuer, $connection->name),
                $pending->codeVerifier,
                $pending->nonce,
            );
        } catch (IdentityProviderFailed) {
            return $refuse(ExternalSignInFailure::ProviderFailed);
        }
        if (! $asserted->provider->equals($connection->name)) {
            return $refuse(ExternalSignInFailure::ProviderFailed);
        }

        $account = ($this->resolveAccount)($asserted, $this->access->pools($client));
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
            $connection->name,
            $pending->nextUrl,
            $pending->clientId,
            $callback->currentSessionId,
        );
    }
}
