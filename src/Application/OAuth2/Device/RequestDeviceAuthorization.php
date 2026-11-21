<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Device;

use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\ReadRequestedAccess;
use Clavia\Application\OAuth2\Token\TokenRequest;
use Clavia\Application\Port\DeviceAuthorizationStore;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\OAuth2\DeviceAuthorization;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\OAuth2\UserCode;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use RuntimeException;

/**
 * `POST /oauth2/device/code` (RFC 8628 §3.1, §3.2): a device's opening move.
 *
 * The device says who it is and what it wants; it gets a device code to poll with, a
 * user code for a person to type at the verification URI, and the polling interval.
 * There is no authorization request in this flow, so what the authorization endpoint
 * checks is checked here: the client is registered for the grant, the scope is one the
 * server or the named API defines, a third-party application never names a system API
 * ({@see ReadRequestedAccess}).
 */
final readonly class RequestDeviceAuthorization
{
    /** A device is a public client more often than not: `none` is the point. */
    public const array AUTH_METHODS = [
        ClientAuthMethod::ClientSecretBasic,
        ClientAuthMethod::ClientSecretPost,
        ClientAuthMethod::None,
    ];

    /** How many user codes to draw before giving up: two live requests sharing one is ~never. */
    private const int ATTEMPTS = 5;

    /**
     * @param non-empty-string $verificationUri Where a person approves: `https://auth.{domain}/auth/device`.
     * @param positive-int     $lifetimeSeconds `CLAVIA_DEVICE_CODE_LIFETIME`.
     * @param positive-int     $interval        `CLAVIA_DEVICE_POLL_INTERVAL`.
     */
    public function __construct(
        private ClientAuthenticator $authenticator,
        private ReadRequestedAccess $requestedAccess,
        private DeviceAuthorizationStore $store,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private Clock $clock,
        private string $verificationUri,
        private int $lifetimeSeconds,
        private int $interval,
    ) {
    }

    /**
     * @throws OAuth2Error `invalid_client` when no client authenticates, `unauthorized_client` when
     *                     it is not registered for the grant, and what {@see ReadRequestedAccess}
     *                     refuses; `invalid_request` for a repeated parameter.
     */
    public function __invoke(TokenRequest $request): DeviceAuthorizationStarted
    {
        $client = $this->authenticator->authenticate($request->credentials(), self::AUTH_METHODS);

        $parameters = $request->parameters;
        $repeated = $parameters->repeated();
        if ($repeated !== []) {
            throw OAuth2Error::invalidRequest(sprintf("Repeated '%s' parameter.", $repeated[0]));
        }
        if (! $client->mayUseGrant(GrantType::DeviceCode)) {
            throw OAuth2Error::unauthorizedClient('The client is not registered for the device code grant.');
        }

        $access = ($this->requestedAccess)($parameters, $client);
        $now = $this->clock->now();

        for ($attempt = 0; $attempt < self::ATTEMPTS; ++$attempt) {
            $deviceCode = $this->secrets->token();
            $userCode = UserCode::generate($this->random);
            $opened = $this->store->open(DeviceAuthorization::request(
                Digest::of($deviceCode),
                $userCode,
                $client->id,
                $access->scope,
                $access->target?->identifier,
                $now,
                $this->lifetimeSeconds,
                $this->interval,
            ));
            if ($opened) {
                return new DeviceAuthorizationStarted(
                    $deviceCode,
                    $userCode->value,
                    $this->verificationUri,
                    $this->verificationUri . '?' . http_build_query(
                        ['user_code' => $userCode->value],
                        '',
                        '&',
                        PHP_QUERY_RFC3986,
                    ),
                    $this->lifetimeSeconds,
                    $this->interval,
                );
            }
        }

        throw new RuntimeException('No free user code could be drawn for a device authorization.');
    }
}
