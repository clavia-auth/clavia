<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OAuth2;

use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\OAuth2\Device\RequestDeviceAuthorization;
use Clavia\Application\OAuth2\Token\TokenRequest;
use Clavia\Domain\OAuth2\OAuth2Error;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /oauth2/device/code` — the device authorization endpoint (RFC 8628 §3.1). Errors
 * are the token endpoint's (§3.2).
 */
final readonly class DeviceAuthorizationHandler implements RequestHandlerInterface
{
    public function __construct(
        private RequestDeviceAuthorization $requestAuthorization,
        private OAuth2Responder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $authorization = $request->getHeaderLine('Authorization');

        try {
            $started = ($this->requestAuthorization)(new TokenRequest(
                RequestParameterReader::form($request),
                $authorization === '' ? null : $authorization,
            ));
        } catch (OAuth2Error $error) {
            return $this->responder->tokenError($error);
        }

        return $this->responder->success([
            'device_code' => $started->deviceCode,
            'user_code' => $started->userCode,
            'verification_uri' => $started->verificationUri,
            'verification_uri_complete' => $started->verificationUriComplete,
            'expires_in' => $started->expiresIn,
            'interval' => $started->interval,
        ]);
    }
}
