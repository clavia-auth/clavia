<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Token;

use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\Dpop\JwkThumbprint;
use Clavia\Domain\OAuth2\Event\AccessTokenIssued;
use Clavia\Domain\OAuth2\Event\RefreshTokenReplayed;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\OAuth2\Refresh;
use Clavia\Domain\OAuth2\RefreshTokenId;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * `grant_type=refresh_token` (RFC 6749 §6), with unconditional rotation: every refresh
 * spends the token presented and issues a new access token *and* a new refresh token.
 *
 * Rotation is what makes a leak detectable. A token presented after it was spent means
 * two parties hold the chain, and there is no telling which one is asking: the whole
 * family is revoked, with every access token it minted (RFC 6749 §10.4). The legitimate
 * person signs in again; whoever took the token gets nothing more. There is no grace
 * period for a reuse — it would be a window in which a replay goes unnoticed — so a
 * client must serialise its own refreshes.
 *
 * The exchange is one transaction on the locked row, committed whatever the outcome, so
 * two refreshes with one token cannot both win and a replay's revocation sticks. Only a
 * refresh that succeeds spends the token: one refused for asking too much, for an
 * account deactivated or for roles taken away leaves it as it was, so `used` means
 * "refreshed" and nothing weaker. A token presented by another client is refused without
 * being burnt: client ids are public, so a thief would present the right one.
 *
 * Re-checked on every refresh rather than trusted from the token: the account, and what
 * its roles grant on the API now ({@see UserScope}). No ID token is issued — a refresh
 * renews access, not the sign-in (OIDC Core §12.2) — and public clients may refresh,
 * which OAuth 2.1 §4.3.1 allows precisely because tokens rotate.
 */
final readonly class RefreshTokenGrant implements Grant
{
    /**
     * @param positive-int $accessTokenLifetimeSeconds
     * @param positive-int $refreshTokenLifetimeSeconds The idle limit of a refresh token.
     */
    public function __construct(
        private RefreshTokenRepository $refreshTokens,
        private AccessTokenRepository $tokens,
        private AccessTokenMinter $accessTokens,
        private UserRepository $users,
        private TransactionManager $transactions,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private Clock $clock,
        private UserScope $userScope,
        private int $accessTokenLifetimeSeconds,
        private int $refreshTokenLifetimeSeconds,
        private DomainEvents $events,
    ) {
    }

    #[\Override]
    public function type(): GrantType
    {
        return GrantType::RefreshToken;
    }

    #[\Override]
    public function acceptedAuthMethods(): array
    {
        return [ClientAuthMethod::ClientSecretBasic, ClientAuthMethod::ClientSecretPost, ClientAuthMethod::None];
    }

    #[\Override]
    public function issue(RequestParameters $parameters, Client $client, ?JwkThumbprint $dpopKey = null): IssuedToken
    {
        $presented = $parameters->get('refresh_token');
        if ($presented === null) {
            throw OAuth2Error::invalidRequest("Missing 'refresh_token' parameter.");
        }

        try {
            $requested = ScopeSet::fromString($parameters->get('scope') ?? '');
        } catch (InvalidValue) {
            throw OAuth2Error::invalidScope('The requested scope is malformed.');
        }

        $result = $this->transactions->transactional(
            fn (): IssuedToken|OAuth2Error => $this->refresh($presented, $requested, $client, $dpopKey),
        );

        return $result instanceof OAuth2Error ? throw $result : $result;
    }

    /**
     * @param ScopeSet $requested Empty when the request named none: the token's ceiling then.
     */
    private function refresh(
        #[\SensitiveParameter] string $presented,
        ScopeSet $requested,
        Client $client,
        ?JwkThumbprint $dpopKey,
    ): IssuedToken|OAuth2Error {
        $now = $this->clock->now();

        $spent = $this->refreshTokens->lockForRefresh(Digest::of($presented));
        if ($spent === null) {
            return self::invalid();
        }

        $refresh = $spent->examine($client->id, $now);
        if ($refresh === Refresh::Replayed) {
            $this->refreshTokens->revokeFamily($spent->familyId, $now);
            $this->tokens->revokeFamily($spent->familyId, $now);
            $this->events->dispatch(new RefreshTokenReplayed($spent->userId, $spent->clientId, $client->id));
        }
        if ($refresh !== Refresh::Usable) {
            // Unknown, foreign, revoked, replayed and expired tokens are one answer.
            return self::invalid();
        }

        // RFC 6749 §6: a refresh may narrow the scope, never widen it. Checked before the
        // token is spent: a client that over-asks keeps its session.
        $ceiling = $requested->isEmpty() ? $spent->scope : $requested;
        if (! $ceiling->isSubsetOf($spent->scope)) {
            return OAuth2Error::invalidScope('A refresh may not ask for more than was originally granted.');
        }

        $user = $this->users->find($spent->userId);
        if ($user === null || ! $user->isActive()) {
            return OAuth2Error::invalidGrant("There is no active user for this 'refresh_token'.");
        }

        $scope = $this->userScope->now($ceiling, $user->id, $spent->audience);
        if ($scope instanceof OAuth2Error) {
            return $scope;
        }

        $spent->spend($now);
        $this->refreshTokens->save($spent);

        $refreshValue = $this->secrets->token();
        // A client that gave something up does not get it back by asking: the narrowed
        // scope is the ceiling of the rest of the chain.
        $successor = $spent->succeededBy(
            RefreshTokenId::generate($this->random),
            Digest::of($refreshValue),
            $ceiling,
            $now,
            $this->refreshTokenLifetimeSeconds,
        );
        $this->refreshTokens->add($successor);

        $minted = $this->accessTokens->mint(
            fn (AccessTokenId $id, Digest $digest): AccessToken => AccessToken::issueFromRefresh(
                $id,
                $digest,
                $successor,
                $scope,
                $now,
                $this->accessTokenLifetimeSeconds,
            ),
            $dpopKey,
        );
        $token = $minted->token;
        $value = $minted->value;
        $this->events->dispatch(new AccessTokenIssued($token, GrantType::RefreshToken, true));

        return new IssuedToken(
            $value,
            $token->tokenType(),
            $token->lifetimeFrom($now),
            $token->scope,
            null,
            $refreshValue,
        );
    }

    private static function invalid(): OAuth2Error
    {
        return OAuth2Error::invalidGrant("Invalid 'refresh_token'.");
    }
}
