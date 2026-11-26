<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\ConsentStateStore;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Consent\PendingConsent;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\UiLocales;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use JsonException;

/**
 * Requests on hold for the consent screen, as JSON under `consent-state:<digest of the
 * handle>`, for {@see PendingConsent::LIFETIME_SECONDS}. Read in place to show the
 * screen; claimed with `GETDEL` to decide, so a request is decided once.
 */
final readonly class RedisConsentStateStore implements ConsentStateStore
{
    private const string PREFIX = 'consent-state';

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function park(#[\SensitiveParameter] string $handle, PendingConsent $pending): void
    {
        $this->redis->client()->setex(
            Keys::forSecret(self::PREFIX, $handle),
            PendingConsent::LIFETIME_SECONDS,
            json_encode(
                [
                    'resume_at' => $pending->resumeAt,
                    'redirect_uri' => $pending->redirectUri,
                    'state' => $pending->state,
                    'user_id' => $pending->userId->value,
                    'client_id' => $pending->clientId->value,
                    'scope' => $pending->scope->toString(),
                    'resource_server_id' => $pending->resourceServerId?->value,
                    'ui_locales' => $pending->uiLocales->toString(),
                ],
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
            ),
        );
    }

    #[\Override]
    public function find(#[\SensitiveParameter] string $handle): ?PendingConsent
    {
        if ($handle === '') {
            return null;
        }

        /** @var mixed $raw */
        $raw = $this->redis->client()->get(Keys::forSecret(self::PREFIX, $handle));

        return self::decode($raw);
    }

    #[\Override]
    public function claim(#[\SensitiveParameter] string $handle): ?PendingConsent
    {
        if ($handle === '') {
            return null;
        }

        /** @var mixed $raw */
        $raw = $this->redis->client()->getDel(Keys::forSecret(self::PREFIX, $handle));

        return self::decode($raw);
    }

    private static function decode(mixed $raw): ?PendingConsent
    {
        if (! is_string($raw)) {
            return null;
        }

        try {
            /** @var mixed $data */
            $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
            if (! is_array($data)) {
                return null;
            }
            /** @var mixed $resumeAt */
            $resumeAt = $data['resume_at'] ?? null;
            /** @var mixed $redirectUri */
            $redirectUri = $data['redirect_uri'] ?? null;
            /** @var mixed $state */
            $state = $data['state'] ?? null;
            /** @var mixed $userId */
            $userId = $data['user_id'] ?? null;
            /** @var mixed $clientId */
            $clientId = $data['client_id'] ?? null;
            /** @var mixed $scope */
            $scope = $data['scope'] ?? null;
            /** @var mixed $resourceServerId */
            $resourceServerId = $data['resource_server_id'] ?? null;
            /** @var mixed $uiLocales */
            $uiLocales = $data['ui_locales'] ?? null;
            if (
                ! is_string($resumeAt)
                || ! is_string($redirectUri)
                || ! is_string($userId)
                || ! is_string($clientId)
                || ! is_string($scope)
            ) {
                return null;
            }

            return new PendingConsent(
                $resumeAt,
                $redirectUri,
                is_string($state) ? $state : null,
                UserId::fromString($userId),
                ClientId::fromString($clientId),
                ScopeSet::fromString($scope),
                is_string($resourceServerId) ? ResourceServerId::fromString($resourceServerId) : null,
                UiLocales::fromString(is_string($uiLocales) ? $uiLocales : null),
            );
        } catch (JsonException | InvalidValue) {
            // An entry this code cannot read is an entry that is not there.
            return null;
        }
    }
}
