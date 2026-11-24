<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OAuth2;

use Clavia\Adapter\Primary\Http\Shared\AccessTokenCredentials;
use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Application\Clients\Registration\ClientConfiguration;
use Clavia\Application\Clients\Registration\DeleteClientConfiguration;
use Clavia\Application\Clients\Registration\ReadClientConfiguration;
use Clavia\Application\Clients\Registration\RegistrationAccessTokenRejected;
use Clavia\Application\Clients\Registration\RegistrationRefused;
use Clavia\Application\Clients\Registration\UpdateClientConfiguration;
use Clavia\Application\OAuth2\ProtectedResource\TokenScheme;
use Clavia\Domain\OAuth2\BearerTokenError;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/oauth2/register/{client_id}`, the client configuration endpoint (RFC 7592 §2): `GET` reads it,
 * `PUT` replaces its metadata, `DELETE` removes the client. The caller proves itself with the
 * registration access token it was handed (`Authorization: Bearer`), which answers only for a client
 * that registered itself. Exists only when registration is on.
 */
final readonly class ClientConfigurationHandler implements RequestHandlerInterface
{
    /** @param non-empty-string $issuer */
    public function __construct(
        private ReadClientConfiguration $read,
        private UpdateClientConfiguration $update,
        private DeleteClientConfiguration $delete,
        private OAuth2Responder $responder,
        private BearerChallenger $challenger,
        private ResponseFactoryInterface $responses,
        private string $issuer,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $credentials = AccessTokenCredentials::fromRequest($request);
        } catch (BearerTokenError $error) {
            return $this->challenger->refuse($error);
        }
        $token = $credentials?->scheme === TokenScheme::Bearer ? $credentials->accessToken : null;
        /** @var mixed $clientId */
        $clientId = $request->getAttribute('client_id');
        if (! is_string($clientId)) {
            throw new LogicException('Routed without a client_id.');
        }

        try {
            return match ($request->getMethod()) {
                'GET' => $this->describe(($this->read)($token, $clientId)),
                'PUT' => $this->describe(($this->update)($token, $clientId, ClientMetadataBody::members($request))),
                'DELETE' => $this->deleted($token, $clientId),
                default => throw new LogicException('Routed with a method the handler does not serve.'),
            };
        } catch (RegistrationAccessTokenRejected $refusal) {
            return $credentials === null
                ? $this->challenger->missing()
                : $this->challenger->refuse(BearerTokenError::invalidToken($refusal->getMessage()));
        } catch (RegistrationRefused $refusal) {
            return $this->responder->registrationRefused($refusal);
        }
    }

    private function describe(ClientConfiguration $configuration): ResponseInterface
    {
        return $this->responder->success(ClientInformation::of(
            $configuration->client,
            $configuration->registration,
            $this->issuer,
            registrationAccessToken: $configuration->registrationAccessToken,
        ));
    }

    /** §2.3: `204`, no body. */
    private function deleted(?string $token, string $clientId): ResponseInterface
    {
        ($this->delete)($token, $clientId);

        return $this->responses->createResponse(
            StatusCodeInterface::STATUS_NO_CONTENT,
        )->withHeader('Cache-Control', 'no-store');
    }
}
