<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\ClientAuthentication;

use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\Shared\InvalidValue;

/**
 * Establishes which client is calling an endpoint (RFC 6749 §2.3, §3.2.1).
 *
 * Each method the endpoint accepts is tried in turn — HTTP Basic, then credentials in
 * the body, then no authentication at all — and a method only succeeds when it is the
 * one the client is *registered* with. That last condition is what stops a confidential
 * client's id from being used as if it were a public client: naming the client without
 * its secret is a valid `none` authentication only for a client registered as `none`.
 *
 * Every failure is the same `invalid_client`, whatever went wrong: an unknown client, a
 * wrong secret and the wrong method are not told apart for the caller.
 */
final readonly class ClientAuthenticator
{
    /**
     * The order in which presented credentials are looked at: the strongest proof first,
     * a bare identifier last.
     */
    private const array ORDER = [
        ClientAuthMethod::ClientSecretBasic,
        ClientAuthMethod::ClientSecretPost,
        ClientAuthMethod::None,
    ];

    public function __construct(
        private ClientRepository $clients,
        private PasswordHasher $hasher,
    ) {
    }

    /**
     * @param list<ClientAuthMethod> $accepted The methods the endpoint accepts.
     *
     * @throws OAuth2Error `invalid_client` when no accepted method identifies a client.
     */
    public function authenticate(ClientCredentials $credentials, array $accepted): Client
    {
        foreach (self::ORDER as $method) {
            if (! in_array($method, $accepted, true)) {
                continue;
            }

            $client = match ($method) {
                ClientAuthMethod::ClientSecretBasic => $this->withBasic($credentials),
                ClientAuthMethod::ClientSecretPost => $this->withPostedSecret($credentials),
                ClientAuthMethod::None => $this->withoutSecret($credentials),
            };

            if ($client !== null && $client->authMethod === $method) {
                return $client;
            }
        }

        throw OAuth2Error::invalidClient('Client authentication failed.');
    }

    /**
     * HTTP Basic (RFC 6749 §2.3.1): `client_id:client_secret`, each form-urlencoded
     * before being joined and base64-encoded.
     */
    private function withBasic(ClientCredentials $credentials): ?Client
    {
        $header = $credentials->authorizationHeader ?? '';
        if (preg_match('/^Basic +([A-Za-z0-9+\/]+=*)$/Di', $header, $match) !== 1) {
            return null;
        }

        $decoded = base64_decode($match[1], true);
        $separator = $decoded === false ? false : strpos($decoded, ':');
        if ($decoded === false || $separator === false) {
            return null;
        }

        // Split at the first colon: a client id cannot hold one, a secret can.
        $clientId = substr($decoded, 0, $separator);
        $secret = substr($decoded, $separator + 1);

        return $this->verified(urldecode($clientId), urldecode($secret));
    }

    private function withPostedSecret(ClientCredentials $credentials): ?Client
    {
        $clientId = $credentials->body->get('client_id');
        $secret = $credentials->body->get('client_secret');

        return $clientId === null || $secret === null ? null : $this->verified($clientId, $secret);
    }

    private function withoutSecret(ClientCredentials $credentials): ?Client
    {
        $clientId = $credentials->body->get('client_id');
        if ($clientId === null || $credentials->body->get('client_secret') !== null) {
            return null;
        }

        return $this->find($clientId);
    }

    private function verified(string $clientId, #[\SensitiveParameter] string $secret): ?Client
    {
        $client = $this->find($clientId);
        $hash = $client?->secretHash();

        return $client !== null && $hash !== null && $this->hasher->verify($secret, $hash) ? $client : null;
    }

    private function find(string $clientId): ?Client
    {
        try {
            return $this->clients->find(ClientId::fromString($clientId));
        } catch (InvalidValue) {
            return null;
        }
    }
}
