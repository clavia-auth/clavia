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
 * A request uses exactly one method, and which one is read from what it carries: an
 * `Authorization` header means HTTP Basic, a `client_secret` in the body means
 * `client_secret_post`, a bare `client_id` means no authentication. Nothing is tried
 * "in turn": credentials that fail are a failed request, never a reason to look for
 * other credentials elsewhere in it (§2.3: "The client MUST NOT use more than one
 * authentication method in each request").
 *
 * The method then has to be one the endpoint accepts and the one the client is
 * *registered* with. That last condition is what stops a confidential client's id from
 * being used as if it were a public client: naming the client without its secret is a
 * valid `none` authentication only for a client registered as `none`.
 *
 * Every failure is the same `invalid_client`, whatever went wrong: an unknown client, a
 * wrong secret, the wrong method and mixed methods are not told apart for the caller.
 */
final readonly class ClientAuthenticator
{
    public function __construct(
        private ClientRepository $clients,
        private PasswordHasher $hasher,
    ) {
    }

    /**
     * @param list<ClientAuthMethod> $accepted The methods the endpoint accepts.
     *
     * @throws OAuth2Error `invalid_client` when the request does not authenticate a client with one
     *                     accepted method, the one that client is registered with.
     */
    public function authenticate(ClientCredentials $credentials, array $accepted): Client
    {
        [$method, $client] = $this->presented($credentials);

        if ($client === null || ! in_array($method, $accepted, true) || $client->authMethod !== $method) {
            throw OAuth2Error::invalidClient('Client authentication failed.');
        }

        return $client;
    }

    /**
     * The one method the request uses, and the client it proves — null when it proves none.
     *
     * @return array{ClientAuthMethod, Client|null}
     */
    private function presented(ClientCredentials $credentials): array
    {
        $clientId = $credentials->body->get('client_id');
        $secret = $credentials->body->get('client_secret');

        if ($credentials->authorizationHeader !== null) {
            return [
                ClientAuthMethod::ClientSecretBasic,
                $this->withBasic($credentials->authorizationHeader, $clientId, $secret),
            ];
        }

        if ($secret !== null) {
            return [
                ClientAuthMethod::ClientSecretPost,
                $clientId === null ? null : $this->verified($clientId, $secret),
            ];
        }

        return [ClientAuthMethod::None, $clientId === null ? null : $this->find($clientId)];
    }

    /**
     * HTTP Basic (RFC 6749 §2.3.1, RFC 7617).
     *
     * An `Authorization` header commits the request to this method: any other scheme,
     * malformed credentials, or a wrong secret fail it. So does a body that also
     * carries a secret, or names another client — many libraries repeat the client's
     * own id in the body, which is harmless and accepted.
     */
    private function withBasic(
        #[\SensitiveParameter] string $header,
        ?string $bodyClientId,
        #[\SensitiveParameter] ?string $bodySecret,
    ): ?Client {
        if (preg_match('/^Basic +([A-Za-z0-9+\/]+=*)$/Di', $header, $match) !== 1) {
            return null;
        }

        $decoded = base64_decode($match[1], true);
        $separator = $decoded === false ? false : strpos($decoded, ':');
        if ($decoded === false || $separator === false) {
            return null;
        }

        // Split at the first colon: a client id cannot hold one, a secret can. Each half
        // was form-encoded before being joined (RFC 6749 §2.3.1).
        $clientId = urldecode(substr($decoded, 0, $separator));
        $secret = urldecode(substr($decoded, $separator + 1));

        if ($bodySecret !== null || ($bodyClientId !== null && $bodyClientId !== $clientId)) {
            return null;
        }

        return $this->verified($clientId, $secret);
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
