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
use Clavia\Application\OAuth2\Token\TokenRequest;
use Clavia\Application\OAuth2\TokenManagement\IntrospectToken;
use Clavia\Application\OAuth2\TokenManagement\TokenIntrospection;
use Clavia\Domain\OAuth2\OAuth2Error;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /oauth2/introspect` — RFC 7662 §2.
 *
 * The answer is a JSON object with `active` and, for an active token, its metadata: the
 * client it was issued to, its scope, the issuer, `iat` and `exp`, the API it is for
 * (`aud`), and for one issued on a person's behalf `sub` — the same value the person's ID
 * token carries — `username`, and, for a sign-in this server witnessed, `auth_time` and `acr`
 * (RFC 9470 §6.2). A token issued to a client as itself has no subject,
 * and says so by having none.
 */
final readonly class IntrospectionHandler implements RequestHandlerInterface
{
    public function __construct(
        private IntrospectToken $introspect,
        private OAuth2Responder $responder,
        private string $issuer,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $authorization = $request->getHeaderLine('Authorization');

        try {
            $introspection = ($this->introspect)(new TokenRequest(
                RequestParameterReader::form($request),
                $authorization === '' ? null : $authorization,
                ClientAddress::of($request),
            ));
        } catch (OAuth2Error $error) {
            return $this->responder->tokenError($error);
        } catch (TooManyFailedRequests $refusal) {
            return $this->responder->tooManyFailures($refusal);
        }

        return $this->responder->success($this->payload($introspection));
    }

    /**
     * @return array<string, mixed>
     */
    private function payload(?TokenIntrospection $introspection): array
    {
        if ($introspection === null) {
            return ['active' => false];
        }

        $payload = [
            'active' => true,
            'client_id' => $introspection->clientId->value,
            'scope' => $introspection->scope->toString(),
            'iss' => $this->issuer,
            'iat' => $introspection->issuedAt->getTimestamp(),
            'exp' => $introspection->expiresAt->getTimestamp(),
        ];
        if ($introspection->tokenType !== null) {
            $payload['token_type'] = $introspection->tokenType;
        }
        if ($introspection->audience !== null) {
            $payload['aud'] = $introspection->audience->value;
        }
        if ($introspection->subject !== null) {
            $payload['sub'] = $introspection->subject->value;
        }
        if ($introspection->username !== null) {
            $payload['username'] = $introspection->username;
        }
        if ($introspection->authenticatedAt !== null) {
            $payload['auth_time'] = $introspection->authenticatedAt->getTimestamp();
        }
        if ($introspection->acr !== null) {
            $payload['acr'] = $introspection->acr;
        }

        return $payload;
    }
}
