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
use Clavia\Application\Oidc\IdTokenIssuer;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\OAuth2\Dpop\JwkThumbprint;
use Clavia\Domain\OAuth2\Event\AccessTokenIssued;
use Clavia\Domain\OAuth2\Event\AuthorizationCodeReplayed;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\OAuth2\Redemption;
use Clavia\Domain\OAuth2\RefreshToken;
use Clavia\Domain\OAuth2\RefreshTokenId;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Clavia\Domain\Oidc\OidcScope;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * `grant_type=authorization_code` (RFC 6749 §4.1.3, with PKCE per RFC 7636 §4.5):
 * exchange a single-use code and its `code_verifier` for an access token — and, for a
 * client registered for the refresh token grant, the first refresh token of a family.
 *
 * The whole exchange is one transaction on a locked row, and it commits whether it
 * succeeds or not:
 *
 * - Two concurrent redemptions of one code cannot both win. The second waits on the
 *   lock, then finds the code spent *and* what the first one issued — and revokes it, as
 *   RFC 6749 §4.1.2 requires of a replay: the access tokens, and the refresh tokens
 *   descended from the code, so a leaked code that already bought a session loses it.
 * - A code is spent before its redirect URI and verifier are examined, and stays spent
 *   when they are wrong: a failed attempt burns the code rather than leaving it for
 *   another guess. That is why refusals travel out of the transaction as values and are
 *   only thrown once it has committed.
 * - What cannot be issued is not issued at all. A server fault — no key to sign the ID
 *   token of an OpenID Connect request — throws inside the transaction and rolls all of
 *   it back: no access token goes out without its ID token, and the code stays unspent
 *   for a retry once the fault is fixed.
 */
final readonly class AuthorizationCodeGrant implements Grant
{
    /**
     * @param positive-int $accessTokenLifetimeSeconds
     * @param positive-int $refreshTokenLifetimeSeconds         The idle limit of a refresh token.
     * @param positive-int $refreshTokenAbsoluteLifetimeSeconds The longest a family may live.
     */
    public function __construct(
        private AuthorizationCodeRepository $codes,
        private AccessTokenRepository $tokens,
        private AccessTokenMinter $accessTokens,
        private RefreshTokenRepository $refreshTokens,
        private UserRepository $users,
        private TransactionManager $transactions,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private Clock $clock,
        private IdTokenIssuer $idTokens,
        private UserScope $userScope,
        private int $accessTokenLifetimeSeconds,
        private int $refreshTokenLifetimeSeconds,
        private int $refreshTokenAbsoluteLifetimeSeconds,
        private DomainEvents $events,
    ) {
    }

    #[\Override]
    public function type(): GrantType
    {
        return GrantType::AuthorizationCode;
    }

    /**
     * `none` is accepted so that public clients — the PKCE case this grant exists to
     * serve — can reach the token endpoint at all.
     */
    #[\Override]
    public function acceptedAuthMethods(): array
    {
        return [ClientAuthMethod::ClientSecretBasic, ClientAuthMethod::ClientSecretPost, ClientAuthMethod::None];
    }

    #[\Override]
    public function issue(RequestParameters $parameters, Client $client, ?JwkThumbprint $dpopKey = null): IssuedToken
    {
        $code = $parameters->get('code');
        if ($code === null) {
            throw OAuth2Error::invalidRequest("Missing 'code' parameter.");
        }

        $result = $this->transactions->transactional(
            fn (): IssuedToken|OAuth2Error => $this->exchange($code, $parameters, $client, $dpopKey),
        );

        return $result instanceof OAuth2Error ? throw $result : $result;
    }

    private function exchange(
        #[\SensitiveParameter] string $presentedCode,
        RequestParameters $parameters,
        Client $client,
        ?JwkThumbprint $dpopKey,
    ): IssuedToken|OAuth2Error {
        $now = $this->clock->now();

        $code = $this->codes->lockForRedemption(Digest::of($presentedCode));
        if ($code === null) {
            return OAuth2Error::invalidGrant("Invalid 'code'.");
        }

        $redemption = $code->redeem($client->id, $now);

        if ($redemption === Redemption::Replayed) {
            // A code seen twice has leaked, and there is no telling which of the two
            // callers was legitimate: revoke what it already produced (RFC 6749 §4.1.2).
            $this->tokens->revokeIssuedFrom($code->id, $now);
            $this->refreshTokens->revokeIssuedFrom($code->id, $now);
            $this->events->dispatch(new AuthorizationCodeReplayed($code->userId, $code->clientId, $client->id));
        }
        if ($redemption !== Redemption::Redeemed) {
            // Unknown, foreign, replayed and expired codes are one answer to the caller.
            return OAuth2Error::invalidGrant("Invalid 'code'.");
        }

        $this->codes->save($code);

        $refusal = $this->refusal($code, $parameters);
        if ($refusal !== null) {
            return $refusal;
        }

        // Re-checked now rather than trusted from when the code was issued: an account
        // deactivated in between must not yield a token.
        $user = $this->users->find($code->userId);
        if ($user === null || ! $user->isActive()) {
            return OAuth2Error::invalidGrant("There is no active user for this 'code'.");
        }

        $scope = $this->userScope->now($code->scope, $user->id, $code->audience);
        if ($scope instanceof OAuth2Error) {
            return $scope;
        }

        return $this->mint($code, $user, $scope, $client->mayUseGrant(GrantType::RefreshToken), $dpopKey);
    }

    /**
     * The checks made once the code is spent. Any of them failing leaves it spent.
     */
    private function refusal(AuthorizationCode $code, RequestParameters $parameters): ?OAuth2Error
    {
        // RFC 6749 §4.1.3: the redirect URI must be the one the code was issued to.
        if ($parameters->get('redirect_uri') !== $code->redirectUri) {
            return OAuth2Error::invalidGrant("Invalid 'redirect_uri'.");
        }

        $verifier = $parameters->get('code_verifier');
        if ($code->challenge === null) {
            // OAuth 2.1 §4.1.3: a verifier for a code issued without a challenge is refused —
            // accepting it would let a downgrade pass for PKCE. The nonce binds this one.
            return $verifier === null
                ? null
                : OAuth2Error::invalidGrant("The 'code' was issued without PKCE: a 'code_verifier' cannot match it.");
        }
        if ($verifier === null) {
            return OAuth2Error::invalidRequest("Missing 'code_verifier' parameter.");
        }

        try {
            $verifier = CodeVerifier::fromString($verifier);
        } catch (InvalidValue) {
            return OAuth2Error::invalidRequest("Invalid 'code_verifier'.");
        }

        if (! $code->challenge->isSatisfiedBy($verifier)) {
            return OAuth2Error::invalidGrant('Code challenge failed.');
        }

        return null;
    }

    /**
     * The access token; the first refresh token of a family when the client may refresh;
     * and — for an OpenID Connect request — the ID token beside them (OIDC Core §3.1.3.3).
     * All are written in the redemption's transaction: if the ID token cannot be signed,
     * nothing survives without it, and the code is not spent.
     */
    private function mint(
        AuthorizationCode $code,
        User $user,
        ScopeSet $scope,
        bool $refreshable,
        ?JwkThumbprint $dpopKey,
    ): IssuedToken {
        $now = $this->clock->now();

        $refreshValue = null;
        $refreshToken = null;
        if ($refreshable) {
            $refreshValue = $this->secrets->token();
            // The family's ceiling is what the person authorized, not what this token
            // carries: a role given back later is honoured by the next refresh.
            $refreshToken = RefreshToken::startFamily(
                RefreshTokenId::generate($this->random),
                Digest::of($refreshValue),
                $code,
                $code->scope,
                $now,
                $this->refreshTokenLifetimeSeconds,
                $this->refreshTokenAbsoluteLifetimeSeconds,
            );
            $this->refreshTokens->add($refreshToken);
        }

        $minted = $this->accessTokens->mint(
            fn (AccessTokenId $id, Digest $digest): AccessToken => AccessToken::issueFromCode(
                $id,
                $digest,
                $code,
                $scope,
                $now,
                $this->accessTokenLifetimeSeconds,
                $refreshToken?->familyId,
            ),
            $dpopKey,
        );
        $token = $minted->token;
        $value = $minted->value;
        $this->events->dispatch(new AccessTokenIssued($token, GrantType::AuthorizationCode, $refreshToken !== null));

        $idToken = $scope->contains(OidcScope::OPENID)
            ? $this->idTokens->issue($code, $user, $value, $now)
            : null;

        return new IssuedToken(
            $value,
            $token->tokenType(),
            $token->lifetimeFrom($now),
            $token->scope,
            $idToken,
            $refreshValue,
        );
    }
}
