<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\IdentityProvider;

use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Adapter\Secondary\Http\OutboundUrlRefused;
use Clavia\Application\Port\IdentityProvider;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\OidcSettings;
use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Shared\InvalidValue;

/**
 * Sign in through any OpenID Connect provider an operator registered: the authorization
 * code flow with PKCE and a `nonce`, then the ID token — verified ({@see IdTokenVerifier})
 * rather than a userinfo call, because its signature is what makes the claims the
 * provider's. `sub` is the subject; `email_verified` is the provider's own statement.
 *
 * The endpoints were checked by the outbound policy when they were discovered; they are
 * checked again before every call, because what a name resolves to can change.
 */
final readonly class OidcIdentityProvider implements IdentityProvider
{
    private AuthorizationCodeExchange $exchange;

    /**
     * @param non-empty-string $clientSecret Decrypted, for the token endpoint only.
     */
    public function __construct(
        private ConnectionName $name,
        private OidcSettings $settings,
        #[\SensitiveParameter] string $clientSecret,
        private ProviderHttp $http,
        private IdTokenVerifier $idTokens,
        private OutboundUrlPolicy $outbound,
    ) {
        $this->exchange = new AuthorizationCodeExchange(
            $http,
            $name->value,
            $settings->authorizationEndpoint->value,
            $settings->tokenEndpoint->value,
            $settings->scope->toString(),
            $settings->clientId,
            $clientSecret,
        );
    }

    #[\Override]
    public function name(): ConnectionName
    {
        return $this->name;
    }

    #[\Override]
    public function authorizationUrl(
        string $redirectUri,
        string $state,
        CodeChallenge $challenge,
        Nonce $nonce,
    ): string {
        return $this->exchange->authorizationUrl($redirectUri, $state, $challenge, $nonce);
    }

    #[\Override]
    public function identify(
        #[\SensitiveParameter] string $code,
        string $redirectUri,
        CodeVerifier $verifier,
        Nonce $nonce,
    ): AssertedIdentity {
        try {
            $this->outbound->check($this->settings->tokenEndpoint->value, 'token_endpoint');
            $this->outbound->check($this->settings->jwksUri->value, 'jwks_uri');
        } catch (OutboundUrlRefused $refused) {
            $this->http->fail($this->name->value, $refused->getMessage());
        }

        $answer = $this->exchange->tokenResponse($code, $redirectUri, $verifier);
        $idToken = $answer['id_token'] ?? null;
        if (! is_string($idToken) || $idToken === '') {
            $this->http->fail($this->name->value, 'the token endpoint returned no ID token.');
        }

        $claims = $this->idTokens->verify($this->name->value, $idToken, $this->settings, $nonce);
        $subject = $claims['sub'] ?? null;
        if (! is_string($subject)) {
            $this->http->fail($this->name->value, 'the ID token carries no subject.');
        }
        /** @var mixed $email */
        $email = $claims['email'] ?? null;

        try {
            return AssertedIdentity::of(
                $this->name,
                $subject,
                is_string($email) ? $email : null,
                ($claims['email_verified'] ?? false) === true,
            );
        } catch (InvalidValue) {
            $this->http->fail($this->name->value, 'the ID token carries an unusable subject.');
        }
    }
}
