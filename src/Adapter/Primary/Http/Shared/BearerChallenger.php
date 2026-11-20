<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Clavia\Domain\OAuth2\BearerErrorCode;
use Clavia\Domain\OAuth2\BearerTokenError;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Encodes a protected resource's refusal of a bearer token (RFC 6750 §3): the status,
 * the `WWW-Authenticate: Bearer` challenge, and an error document saying the same.
 *
 * None of it may be cached: whether a request is refused depends on the token it
 * carried.
 */
final readonly class BearerChallenger
{
    private const array NO_STORE = ['Cache-Control' => 'no-store'];

    /**
     * @param string $realm The protection space named in every challenge: the issuer.
     */
    public function __construct(
        private ResponseFactoryInterface $responses,
        private string $realm,
    ) {
    }

    /**
     * The request carried no bearer credentials. RFC 6750 §3.1: "the resource server
     * SHOULD NOT include an error code or other error information" — just the
     * challenge saying which scheme to use.
     */
    public function missing(): ResponseInterface
    {
        return $this->responses->createResponse(401)
            ->withHeader('WWW-Authenticate', 'Bearer ' . self::parameters(['realm' => $this->realm]))
            ->withHeader('Cache-Control', 'no-store');
    }

    /**
     * The request presented credentials that cannot be used: 400 for a malformed
     * request, 401 for a token that is not valid, 403 for one lacking the scope
     * (RFC 6750 §3.1).
     */
    public function refuse(BearerTokenError $error): ResponseInterface
    {
        $parameters = [
            'realm' => $this->realm,
            'error' => $error->error->value,
            'error_description' => $error->description,
        ];
        if ($error->requiredScope !== null) {
            $parameters['scope'] = $error->requiredScope->toString();
        }

        $status = match ($error->error) {
            BearerErrorCode::InvalidRequest => 400,
            BearerErrorCode::InvalidToken => 401,
            BearerErrorCode::InsufficientScope => 403,
        };

        return new JsonResponse(
            ['error' => $error->error->value, 'error_description' => $error->description],
            $status,
            self::NO_STORE + ['WWW-Authenticate' => 'Bearer ' . self::parameters($parameters)],
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
