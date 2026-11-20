<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External;

use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Application\Port\IdentityProviders;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Authentication\PendingExternalSignIn;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Send a sign-in out to an external provider.
 *
 * The login page's handle, when there is one, says where to come back to; it is read
 * and re-validated now, and the place is kept with the pending sign-in, so it survives
 * however long the person spends at the provider. A fresh `state` handle and PKCE
 * verifier are minted for the round trip; only the handle leaves this server.
 */
final readonly class BeginExternalSignIn
{
    public function __construct(
        private IdentityProviders $providers,
        private ExternalSignInStore $pending,
        private LoginStateStore $loginStates,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private string $issuer,
    ) {
    }

    /**
     * @param string|null $loginState The login page's handle, if the sign-in started from one.
     *
     * @return ExternalSignInStarted|null Null when no configured provider has that name.
     */
    public function __invoke(string $provider, #[\SensitiveParameter] ?string $loginState): ?ExternalSignInStarted
    {
        $identityProvider = $this->providers->find($provider);
        if ($identityProvider === null) {
            return null;
        }

        $loginState = $loginState === '' ? null : $loginState;
        $target = $loginState === null ? null : $this->loginStates->get($loginState);
        $verifier = CodeVerifier::generate($this->random);
        $handle = $this->secrets->token();

        $this->pending->open($handle, new PendingExternalSignIn(
            $identityProvider->name(),
            $verifier,
            LocalPath::orDefault($target?->nextUrl)->value,
            $target?->clientId,
            $loginState,
        ));

        return new ExternalSignInStarted(
            $identityProvider->authorizationUrl(
                ExternalCallbackUrl::for($this->issuer, $identityProvider->name()),
                $handle,
                CodeChallenge::forVerifier($verifier),
            ),
            $handle,
        );
    }
}
