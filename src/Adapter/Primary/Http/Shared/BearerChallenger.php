<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Clavia\Application\OAuth2\ProtectedResource\TokenScheme;
use Clavia\Domain\OAuth2\BearerErrorCode;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\OAuth2\Dpop\DpopAlgorithm;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;

/**
 * Encodes a protected resource's refusal of an access token (RFC 6750 §3): the status, the
 * `WWW-Authenticate` challenge — `Bearer`, or `DPoP` with the algorithms for a DPoP request
 * (RFC 9449 §7.1) — and an error document saying the same.
 *
 * None of it may be cached: whether a request is refused depends on the token it
 * carried.
 */
final readonly class BearerChallenger
{
    private const array NO_STORE = ['Cache-Control' => 'no-store'];

    /**
     * @param string $realm The protection space named in every challenge: the issuer for the
     *                      OIDC endpoints, the Management API's identifier for `/api/v1/*`.
     */
    public function __construct(private string $realm)
    {
    }

    /**
     * The request carried no bearer credentials. RFC 6750 §3.1: "the resource server
     * SHOULD NOT include an error code or other error information" — just the
     * challenge saying which scheme to use, and an empty JSON object, so that every
     * refusal a program receives is a JSON document it can parse.
     */
    public function missing(): ResponseInterface
    {
        return new JsonResponse(
            new \stdClass(),
            401,
            self::NO_STORE + ['WWW-Authenticate' => 'Bearer ' . self::parameters(['realm' => $this->realm])],
        );
    }

    /**
     * The request presented credentials that cannot be used: 400 for a malformed
     * request, 401 for a token that is not valid, 403 for one lacking the scope
     * (RFC 6750 §3.1).
     */
    public function refuse(BearerTokenError $error, TokenScheme $scheme = TokenScheme::Bearer): ResponseInterface
    {
        $parameters = [
            'realm' => $this->realm,
            'error' => $error->error->value,
            'error_description' => $error->description,
        ];
        if ($error->requiredScope !== null) {
            $parameters['scope'] = $error->requiredScope->toString();
        }
        if ($error->requiredAuthentication !== null) {
            // RFC 9470 §3: the levels that would do, for the client's next authorization request.
            $parameters['acr_values'] = implode(' ', $error->requiredAuthentication->acrValues());
        }
        if ($scheme === TokenScheme::Dpop || $error->error === BearerErrorCode::InvalidDpopProof) {
            // RFC 9449 §7.1: a DPoP request is answered in its scheme, naming the algorithms.
            $parameters['algs'] = implode(' ', DpopAlgorithm::supported());
        }

        $status = match ($error->error) {
            BearerErrorCode::InvalidRequest => 400,
            BearerErrorCode::InvalidToken,
            BearerErrorCode::InsufficientUserAuthentication,
            BearerErrorCode::InvalidDpopProof => 401,
            BearerErrorCode::InsufficientScope => 403,
        };
        $challenge = $scheme === TokenScheme::Dpop || $error->error === BearerErrorCode::InvalidDpopProof
            ? 'DPoP '
            : 'Bearer ';

        return new JsonResponse(
            ['error' => $error->error->value, 'error_description' => $error->description],
            $status,
            self::NO_STORE + ['WWW-Authenticate' => $challenge . self::parameters($parameters)],
        );
    }

    /**
     * auth-params as quoted strings (RFC 9110 §11.2), `"` and `\` escaped.
     *
     * @param array<string, string> $parameters
     */
    private static function parameters(array $parameters): string
    {
        $pairs = [];
        foreach ($parameters as $name => $value) {
            $pairs[] = sprintf('%s="%s"', $name, addcslashes($value, '"\\'));
        }

        return implode(', ', $pairs);
    }
}
