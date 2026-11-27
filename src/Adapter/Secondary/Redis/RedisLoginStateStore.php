<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\UiLocales;
use Clavia\Domain\Shared\InvalidValue;
use JsonException;

/**
 * Pending sign-ins in Redis, under `login-state:<digest of the handle>`.
 *
 * The handle is digested for the key, so reading Redis never yields something a
 * browser could present. Entries expire on their own; reading does not extend them.
 */
final readonly class RedisLoginStateStore implements LoginStateStore
{
    private const string PREFIX = 'login-state';

    /** The application a request was for, kept a day under its own key: the client's id and nothing else. */
    private const string APPLICATION_PREFIX = 'login-state-application';

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function put(#[\SensitiveParameter] string $handle, LoginState $state): void
    {
        $this->redis->client()->setex(
            Keys::forSecret(self::PREFIX, $handle),
            LoginState::LIFETIME_SECONDS,
            json_encode(
                [
                    'next_url' => $state->nextUrl,
                    'client_id' => $state->clientId?->value,
                    'ui_locales' => $state->uiLocales->toString(),
                ],
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
            ),
        );
        if ($state->clientId !== null) {
            $this->redis->client()->setex(
                Keys::forSecret(self::APPLICATION_PREFIX, $handle),
                LoginState::APPLICATION_REMEMBERED_SECONDS,
                $state->clientId->value,
            );
        }
    }

    #[\Override]
    public function get(#[\SensitiveParameter] string $handle): ?LoginState
    {
        if ($handle === '') {
            return null;
        }

        $raw = $this->redis->client()->get(Keys::forSecret(self::PREFIX, $handle));
        if (! is_string($raw)) {
            return null;
        }

        try {
            /** @var mixed $data */
            $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
            if (! is_array($data)) {
                return null;
            }

            /** @var mixed $nextUrl */
            $nextUrl = $data['next_url'] ?? null;
            /** @var mixed $clientId */
            $clientId = $data['client_id'] ?? null;

            /** @var mixed $uiLocales */
            $uiLocales = $data['ui_locales'] ?? null;

            return is_string($nextUrl)
                ? new LoginState(
                    $nextUrl,
                    is_string($clientId) ? ClientId::fromString($clientId) : null,
                    UiLocales::fromString(is_string($uiLocales) ? $uiLocales : null),
                )
                : null;
        } catch (JsonException | InvalidValue) {
            // An entry this code cannot read is an entry that is not there.
            return null;
        }
    }

    #[\Override]
    public function forget(#[\SensitiveParameter] string $handle): void
    {
        if ($handle !== '') {
            $this->redis->client()->del(Keys::forSecret(self::PREFIX, $handle));
        }
    }

    #[\Override]
    public function applicationOf(#[\SensitiveParameter] string $handle): ?ClientId
    {
        if ($handle === '') {
            return null;
        }

        $raw = $this->redis->client()->get(Keys::forSecret(self::APPLICATION_PREFIX, $handle));
        try {
            return is_string($raw) ? ClientId::fromString($raw) : null;
        } catch (InvalidValue) {
            return null;
        }
    }
}
