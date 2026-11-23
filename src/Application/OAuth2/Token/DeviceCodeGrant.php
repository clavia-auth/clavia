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
use Clavia\Application\Port\DeviceAuthorizationStore;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\DeviceAuthorization;
use Clavia\Domain\OAuth2\DevicePoll;
use Clavia\Domain\OAuth2\Event\AccessTokenIssued;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\OAuth2\RefreshToken;
use Clavia\Domain\OAuth2\RefreshTokenId;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Clavia\Domain\Oidc\OidcScope;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * The device code grant (RFC 8628 §3.4, §3.5): the device's polling half.
 *
 * Until the person decides, the device hears `authorization_pending`; polling sooner than
 * the interval earns `slow_down` and a longer interval; a refusal is `access_denied`; a
 * code nobody got to in time is `expired_token`. An approval is a token — scoped, as at
 * every issuance, to what the person's roles grant on the API *now* — and the request is
 * consumed as it is issued, so a device code is redeemed once.
 */
final readonly class DeviceCodeGrant implements Grant
{
    /**
     * @param positive-int $accessTokenLifetimeSeconds
     * @param positive-int $refreshTokenLifetimeSeconds
     * @param positive-int $refreshTokenAbsoluteLifetimeSeconds
     */
    public function __construct(
        private DeviceAuthorizationStore $requests,
        private AccessTokenMinter $accessTokens,
        private RefreshTokenRepository $refreshTokens,
        private UserRepository $users,
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
        return GrantType::DeviceCode;
    }

    #[\Override]
    public function acceptedAuthMethods(): array
    {
        return [ClientAuthMethod::ClientSecretBasic, ClientAuthMethod::ClientSecretPost, ClientAuthMethod::None];
    }

    #[\Override]
    public function issue(RequestParameters $parameters, Client $client): IssuedToken
    {
        $deviceCode = $parameters->get('device_code');
        if ($deviceCode === null) {
            throw OAuth2Error::invalidRequest("Missing 'device_code' parameter.");
        }

        $request = $this->requests->findByDeviceCode(Digest::of($deviceCode));
        // Unknown, gone past its grace, or another client's: one answer.
        if ($request === null || ! $request->clientId->equals($client->id)) {
            throw OAuth2Error::invalidGrant("Invalid 'device_code'.");
        }

        $poll = $request->poll($this->clock->now());
        if ($poll === DevicePoll::Pending || $poll === DevicePoll::SlowDown) {
            $this->requests->save($request);
        }

        return match ($poll) {
            DevicePoll::Pending => throw OAuth2Error::authorizationPending('The user has not decided yet.'),
            DevicePoll::SlowDown => throw OAuth2Error::slowDown(sprintf(
                'Polled too often: wait %d seconds between polls.',
                $request->interval(),
            )),
            DevicePoll::Expired => throw OAuth2Error::expiredToken('The device code has expired: start again.'),
            DevicePoll::Denied => throw OAuth2Error::accessDenied('The user did not allow the device.'),
            DevicePoll::Approved => $this->redeem($request, $client),
        };
    }

    /**
     * @throws OAuth2Error
     */
    private function redeem(DeviceAuthorization $request, Client $client): IssuedToken
    {
        // Consumed before anything is issued: of two concurrent polls, one wins.
        if (! $this->requests->consume($request)) {
            throw OAuth2Error::invalidGrant("Invalid 'device_code'.");
        }

        $userId = $request->userId();
        // Re-checked at issuance, as everywhere: an approval by an account deactivated
        // since mints nothing.
        $user = $userId === null ? null : $this->users->find($userId);
        if ($user === null || ! $user->isActive()) {
            throw OAuth2Error::invalidGrant('There is no active user for this device code.');
        }

        $scope = $this->userScope->now($request->scope, $user->id, $request->audience);
        if ($scope instanceof OAuth2Error) {
            throw $scope;
        }

        return $this->mint($request, $user, $scope, $client->mayUseGrant(GrantType::RefreshToken));
    }

    private function mint(DeviceAuthorization $request, User $user, ScopeSet $scope, bool $refreshable): IssuedToken
    {
        $now = $this->clock->now();

        $refreshValue = null;
        $refreshToken = null;
        if ($refreshable) {
            $refreshValue = $this->secrets->token();
            // The family's ceiling is what the person approved, as in the code flow.
            $refreshToken = RefreshToken::startFamilyFor(
                RefreshTokenId::generate($this->random),
                Digest::of($refreshValue),
                $request->clientId,
                $user->id,
                null,
                $request->audience,
                $request->scope,
                $now,
                $this->refreshTokenLifetimeSeconds,
                $this->refreshTokenAbsoluteLifetimeSeconds,
                $request->authentication() ?? AuthenticationContext::unknown(),
            );
            $this->refreshTokens->add($refreshToken);
        }

        $minted = $this->accessTokens->mint(
            fn (AccessTokenId $id, Digest $digest): AccessToken => AccessToken::issueForUser(
                $id,
                $digest,
                $request->clientId,
                $user->id,
                $request->audience,
                $scope,
                $now,
                $this->accessTokenLifetimeSeconds,
                $request->authentication() ?? AuthenticationContext::unknown(),
                $refreshToken?->familyId,
            ),
        );
        $token = $minted->token;
        $value = $minted->value;
        $this->events->dispatch(new AccessTokenIssued($token, GrantType::DeviceCode, $refreshToken !== null));

        $idToken = $scope->contains(OidcScope::OPENID)
            ? $this->idTokens->issueFor(
                $request->clientId,
                null,
                $request->authentication() ?? AuthenticationContext::unknown(),
                $user,
                $value,
                $now,
            )
            : null;

        return new IssuedToken(
            $value,
            AccessToken::TOKEN_TYPE,
            $token->lifetimeFrom($now),
            $token->scope,
            $idToken,
            $refreshValue,
        );
    }
}
