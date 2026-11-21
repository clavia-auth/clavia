<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\TokenManagement;

use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\Token\TokenRequest;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\Event\AccessTokenRevoked;
use Clavia\Domain\OAuth2\Event\RefreshTokenRevoked;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Clavia\Domain\Shared\Clock;

/**
 * `POST /oauth2/revoke` (RFC 7009): a client giving back a token it holds.
 *
 * Any client may — a public one too, with nothing but its `client_id` (§2.1), at sign-out
 * or when it suspects a leak. A refresh token takes its whole family along: every refresh
 * token in the chain and every access token any of them minted (§2.1: the access tokens
 * of the same grant SHOULD go too), which is what a client means by "I am done with this
 * session". An access token goes alone: the client may well be keeping its session.
 *
 * A token that does not exist, or is already revoked, is revoked: there is nothing to
 * reveal and nothing to do (§2.2).
 */
final readonly class RevokeToken
{
    public const array AUTH_METHODS = [
        ClientAuthMethod::ClientSecretBasic,
        ClientAuthMethod::ClientSecretPost,
        ClientAuthMethod::None,
    ];

    public function __construct(
        private ClientAuthenticator $authenticator,
        private IssuedTokens $tokens,
        private AccessTokenRepository $accessTokens,
        private RefreshTokenRepository $refreshTokens,
        private TransactionManager $transactions,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws OAuth2Error `invalid_client` when no client authenticates; `invalid_grant` when the
     *                     token was issued to another client — it is not this one's to give back;
     *                     `invalid_request` or `unsupported_token_type` for a malformed request.
     */
    public function __invoke(TokenRequest $request): void
    {
        $caller = $this->authenticator->authenticate($request->credentials(), self::AUTH_METHODS);
        $token = $this->tokens->find(PresentedToken::from($request->parameters));
        if ($token === null) {
            return;
        }

        if (! $token->clientId->equals($caller->id)) {
            throw OAuth2Error::invalidGrant('The token was issued to another client.');
        }

        $now = $this->clock->now();
        if ($token instanceof AccessToken) {
            $this->transactions->transactional(function () use ($token, $now): void {
                $this->accessTokens->revoke($token->id, $now);
                $this->events->dispatch(new AccessTokenRevoked($token->clientId, $token->userId));
            });

            return;
        }

        $this->transactions->transactional(function () use ($token, $now): void {
            $this->refreshTokens->revokeFamily($token->familyId, $now);
            $this->accessTokens->revokeFamily($token->familyId, $now);
            $this->events->dispatch(new RefreshTokenRevoked($token->clientId, $token->userId));
        });
    }
}
