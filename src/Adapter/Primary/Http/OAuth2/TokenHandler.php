<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OAuth2;

use Clavia\Adapter\Primary\Http\Shared\ClientAddress;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\OAuth2\ClientAuthentication\TooManyFailedRequests;
use Clavia\Application\OAuth2\Token\IssueToken;
use Clavia\Application\OAuth2\Token\TokenRequest;
use Clavia\Domain\OAuth2\OAuth2Error;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

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
        private LoggerInterface $logger,
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
                ClientAddress::of($request),
                array_values($request->getHeader('DPoP')),
            ));
        } catch (OAuth2Error $error) {
            if ($error->reason !== null) {
                $this->logger->info('A DPoP proof was refused at the token endpoint: {reason}', [
                    'reason' => $error->reason,
                ]);
            }

            return $this->responder->tokenError($error);
        } catch (TooManyFailedRequests $refusal) {
            return $this->responder->tooManyFailures($refusal);
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

        $response = $this->responder->success($payload);

        // RFC 9449 §8: the nonce for the client's next proof, without a failed round trip.
        return $token->dpopNonce === null ? $response : $response->withHeader('DPoP-Nonce', $token->dpopNonce);
    }
}
