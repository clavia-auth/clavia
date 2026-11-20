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
use Clavia\Application\OAuth2\Token\IssueToken;
use Clavia\Application\OAuth2\Token\TokenRequest;
use Clavia\Domain\OAuth2\OAuth2Error;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /oauth2/token` — the token endpoint (RFC 6749 §3.2).
 *
 * Parameters come from the form body only — never the query string, where credentials
 * would end up in logs (RFC 6749 §2.3.1).
 */
final readonly class TokenHandler implements RequestHandlerInterface
{
    public function __construct(
        private IssueToken $issueToken,
        private OAuth2Responder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $authorization = $request->getHeaderLine('Authorization');

        try {
            $token = ($this->issueToken)(new TokenRequest(
                RequestParameterReader::form($request),
                $authorization === '' ? null : $authorization,
            ));
        } catch (OAuth2Error $error) {
            return $this->responder->tokenError($error);
        }

        $payload = [
            'token_type' => $token->tokenType,
            'access_token' => $token->accessToken,
            'expires_in' => $token->expiresIn,
        ];
        if (! $token->scope->isEmpty()) {
            $payload['scope'] = $token->scope->toString();
        }
        if ($token->refreshToken !== null) {
            $payload['refresh_token'] = $token->refreshToken;
        }
        if ($token->idToken !== null) {
            $payload['id_token'] = $token->idToken;
        }

        return $this->responder->success($payload);
    }
}
