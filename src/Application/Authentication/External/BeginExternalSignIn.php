<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External;

use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Authentication\PendingExternalSignIn;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Send a sign-in out to the provider behind an external connection.
 *
 * The login page's handle, when there is one, says where to come back to and for which
 * application; it is read and re-validated now, and kept with the pending sign-in, so it
 * survives however long the person spends at the provider. The application must let its
 * users in through the connection — refused, not merely hidden. A fresh `state` handle,
 * PKCE verifier and `nonce` are minted for the round trip; only the handle and the nonce
 * leave this server.
 */
final readonly class BeginExternalSignIn
{
    public function __construct(
        private ConnectionAccess $access,
        private ClientRepository $clients,
        private ExternalSignInStore $pending,
        private LoginStateStore $loginStates,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private string $issuer,
    ) {
    }

    /**
     * @param string      $connection The connection the route named.
     * @param string|null $loginState The login page's handle, if the sign-in started from one.
     *
     * @return ExternalSignInStarted|ExternalSignInUnavailable|null Null when no usable external
     *                                                              connection has that name.
     */
    public function __invoke(
        string $connection,
        #[\SensitiveParameter] ?string $loginState,
    ): ExternalSignInStarted|ExternalSignInUnavailable|null {
        try {
            $usable = $this->access->external(ConnectionName::fromString($connection));
        } catch (InvalidValue) {
            $usable = null;
        }
        if ($usable === null || $usable->provider === null) {
            return null;
        }

        $loginState = $loginState === '' ? null : $loginState;
        $target = $loginState === null ? null : $this->loginStates->get($loginState);
        $clientId = $target?->clientId;
        $client = $clientId === null ? null : $this->clients->find($clientId);
        if (! $this->access->allows($client, $usable->connection->name)) {
            return new ExternalSignInUnavailable($usable->connection->displayName);
        }

        $verifier = CodeVerifier::generate($this->random);
        $nonce = Nonce::fromString($this->secrets->token());
        $handle = $this->secrets->token();

        $this->pending->open($handle, new PendingExternalSignIn(
            $usable->connection->name,
            $verifier,
            LocalPath::orDefault($target?->nextUrl)->value,
            $target?->clientId,
            $loginState,
            $nonce,
        ));

        return new ExternalSignInStarted(
            $usable->provider->authorizationUrl(
                ExternalCallbackUrl::for($this->issuer, $usable->connection->name),
                $handle,
                CodeChallenge::forVerifier($verifier),
                $nonce,
            ),
            $handle,
        );
    }
}
