<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\DeviceAuthorizationStore;
use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\DeviceAuthorization;
use Clavia\Domain\OAuth2\DeviceDecision;
use Clavia\Domain\OAuth2\UserCode;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;
use JsonException;
use LogicException;
use ValueError;

/**
 * Device authorizations in Redis: the request under its user code, and the device code's
 * digest pointing at that user code. Both expire together, the request's life plus the
 * grace in which a late poll still hears `expired_token`.
 *
 * The user code is hashed into its key like every other code (it is low-entropy, so the
 * hash hides it only from a casual reader of the keys); the device code is not stored at
 * all, only its digest.
 */
final readonly class RedisDeviceAuthorizationStore implements DeviceAuthorizationStore
{
    private const string REQUEST_PREFIX = 'device-request';
    private const string DEVICE_CODE_PREFIX = 'device-code';
    private const string INSTANT = 'Y-m-d\TH:i:s.uP';

    public function __construct(
        private RedisConnection $redis,
        private Clock $clock,
    ) {
    }

    #[\Override]
    public function open(DeviceAuthorization $authorization): bool
    {
        $ttl = $authorization->retentionFrom($this->clock->now());
        $client = $this->redis->client();

        $stored = $client->set(self::requestKey($authorization->userCode), self::encode($authorization), [
            'NX',
            'EX' => $ttl,
        ]);
        if ($stored !== true) {
            return false;
        }
        $client->setex(self::deviceKey($authorization->deviceCode), $ttl, $authorization->userCode->value);

        return true;
    }

    #[\Override]
    public function findByDeviceCode(Digest $deviceCode): ?DeviceAuthorization
    {
        /** @var mixed $userCode */
        $userCode = $this->redis->client()->get(self::deviceKey($deviceCode));
        if (! is_string($userCode)) {
            return null;
        }

        try {
            $found = $this->findByUserCode(UserCode::fromTyped($userCode));
        } catch (InvalidValue) {
            return null;
        }

        return $found !== null && $found->deviceCode->equals($deviceCode) ? $found : null;
    }

    #[\Override]
    public function findByUserCode(UserCode $userCode): ?DeviceAuthorization
    {
        return self::decode($this->redis->client()->get(self::requestKey($userCode)));
    }

    #[\Override]
    public function save(DeviceAuthorization $authorization): void
    {
        // Only while it is kept, and for no longer: a save never revives an expired entry.
        $this->redis->client()->set(self::requestKey($authorization->userCode), self::encode($authorization), [
            'XX',
            'KEEPTTL',
        ]);
    }

    #[\Override]
    public function consume(DeviceAuthorization $authorization): bool
    {
        $client = $this->redis->client();
        $deleted = $client->del(self::requestKey($authorization->userCode));
        $client->del(self::deviceKey($authorization->deviceCode));

        return $deleted === 1;
    }

    private static function requestKey(UserCode $userCode): string
    {
        return Keys::forSecret(self::REQUEST_PREFIX, $userCode->value);
    }

    private static function deviceKey(Digest $deviceCode): string
    {
        return Keys::forIdentifier(self::DEVICE_CODE_PREFIX, $deviceCode->toString());
    }

    private static function encode(DeviceAuthorization $authorization): string
    {
        $authentication = $authorization->authentication();

        return json_encode(
            [
                'device_code' => $authorization->deviceCode->toString(),
                'user_code' => $authorization->userCode->value,
                'client_id' => $authorization->clientId->value,
                'scope' => $authorization->scope->toString(),
                'audience' => $authorization->audience?->value,
                'expires_at' => $authorization->expiresAt->format(self::INSTANT),
                'interval' => $authorization->interval(),
                'decision' => $authorization->decision()->value,
                'last_polled_at' => $authorization->lastPolledAt()?->format(self::INSTANT),
                'user_id' => $authorization->userId()?->value,
                'authenticated_at' => $authentication?->authenticatedAt?->format(self::INSTANT),
                'amr' => $authentication?->methodValues(),
            ],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
        );
    }

    private static function decode(mixed $raw): ?DeviceAuthorization
    {
        if (! is_string($raw)) {
            return null;
        }

        try {
            /** @var mixed $data */
            $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
            if (! is_array($data)) {
                return null;
            }
            /** @var array<string, mixed> $data */
            $interval = $data['interval'] ?? null;
            $amr = $data['amr'] ?? null;
            if (! is_int($interval) || $interval < 1 || ($amr !== null && ! is_array($amr))) {
                return null;
            }
            $userId = self::optionalString($data, 'user_id');
            $authenticatedAt = self::optionalString($data, 'authenticated_at');
            $audience = self::optionalString($data, 'audience');
            $lastPolledAt = self::optionalString($data, 'last_polled_at');

            return DeviceAuthorization::reconstitute(
                Digest::fromHex(self::string($data, 'device_code')),
                UserCode::fromTyped(self::string($data, 'user_code')),
                ClientId::fromString(self::string($data, 'client_id')),
                ScopeSet::fromString(self::string($data, 'scope')),
                $audience === null ? null : Audience::fromString($audience),
                self::instant(self::string($data, 'expires_at')),
                $interval,
                DeviceDecision::from(self::string($data, 'decision')),
                $lastPolledAt === null ? null : self::instant($lastPolledAt),
                $userId === null ? null : UserId::fromString($userId),
                $amr === null ? null : AuthenticationContext::reconstitute(
                    $authenticatedAt === null ? null : self::instant($authenticatedAt),
                    array_map(
                        static fn (mixed $method): AuthenticationMethod
                            => AuthenticationMethod::from(is_string($method) ? $method : ''),
                        array_values($amr),
                    ),
                ),
            );
        } catch (JsonException | InvalidValue | ValueError | LogicException) {
            // An entry this code cannot read is an entry that is not there.
            return null;
        }
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws InvalidValue
     */
    private static function string(array $data, string $field): string
    {
        /** @var mixed $value */
        $value = $data[$field] ?? null;

        return is_string($value) ? $value : throw new InvalidValue(sprintf("'%s' is not a string.", $field));
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws InvalidValue
     */
    private static function optionalString(array $data, string $field): ?string
    {
        /** @var mixed $value */
        $value = $data[$field] ?? null;

        return $value === null || is_string($value)
            ? $value
            : throw new InvalidValue(sprintf("'%s' is not a string.", $field));
    }

    /**
     * @throws InvalidValue
     */
    private static function instant(string $value): DateTimeImmutable
    {
        $instant = DateTimeImmutable::createFromFormat(self::INSTANT, $value);
        if ($instant === false || $instant->format(self::INSTANT) !== $value) {
            throw new InvalidValue('Not an instant.');
        }

        return $instant;
    }
}
