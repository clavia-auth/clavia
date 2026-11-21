<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Domain\Authentication\PendingExternalSignIn;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Shared\InvalidValue;
use JsonException;

/**
 * Pending external sign-ins in Redis, as JSON under `external-sign-in:<digest of the
 * state>`, for {@see PendingExternalSignIn::LIFETIME_SECONDS}. Claimed with `GETDEL`:
 * reading and removing are one command, so a `state` cannot be redeemed twice.
 */
final readonly class RedisExternalSignInStore implements ExternalSignInStore
{
    private const string PREFIX = 'external-sign-in';

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function open(#[\SensitiveParameter] string $handle, PendingExternalSignIn $pending): void
    {
        $this->redis->client()->setex(
            Keys::forSecret(self::PREFIX, $handle),
            PendingExternalSignIn::LIFETIME_SECONDS,
            json_encode(
                [
                    'provider' => $pending->provider->value,
                    'code_verifier' => $pending->codeVerifier->value,
                    'next_url' => $pending->nextUrl,
                    'client_id' => $pending->clientId?->value,
                    'login_state' => $pending->loginState,
                    'nonce' => $pending->nonce->value,
                ],
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
            ),
        );
    }

    #[\Override]
    public function claim(#[\SensitiveParameter] string $handle): ?PendingExternalSignIn
    {
        if ($handle === '') {
            return null;
        }

        /** @var mixed $raw */
        $raw = $this->redis->client()->getDel(Keys::forSecret(self::PREFIX, $handle));
        if (! is_string($raw)) {
            return null;
        }

        try {
            /** @var mixed $data */
            $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
            if (! is_array($data)) {
                return null;
            }
            /** @var mixed $provider */
            $provider = $data['provider'] ?? null;
            /** @var mixed $verifier */
            $verifier = $data['code_verifier'] ?? null;
            /** @var mixed $nextUrl */
            $nextUrl = $data['next_url'] ?? null;
            /** @var mixed $clientId */
            $clientId = $data['client_id'] ?? null;
            /** @var mixed $loginState */
            $loginState = $data['login_state'] ?? null;
            /** @var mixed $nonce */
            $nonce = $data['nonce'] ?? null;
            if (! is_string($provider) || ! is_string($verifier) || ! is_string($nextUrl) || ! is_string($nonce)) {
                return null;
            }

            return new PendingExternalSignIn(
                ConnectionName::fromString($provider),
                CodeVerifier::fromString($verifier),
                $nextUrl,
                is_string($clientId) ? ClientId::fromString($clientId) : null,
                is_string($loginState) && $loginState !== '' ? $loginState : null,
                Nonce::fromString($nonce),
            );
        } catch (JsonException | InvalidValue) {
            // An entry this code cannot read is an entry that is not there.
            return null;
        }
    }
}
