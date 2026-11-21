<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\SessionStore;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;
use DateTimeInterface;
use Exception;
use JsonException;
use ValueError;

/**
 * Browser sessions in Redis: `session:<sha256 of the identifier>` → a JSON document,
 * with the idle window as the key's time-to-live.
 */
final readonly class RedisSessionStore implements SessionStore
{
    private const string PREFIX = 'session';

    /** Microseconds kept: `auth_time` is reported from this, and two sign-ins in one second are two. */
    private const string INSTANT = 'Y-m-d\TH:i:s.uP';

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function save(#[\SensitiveParameter] string $sessionId, Session $session, int $ttlSeconds): void
    {
        $this->redis->client()->setex(
            Keys::forSecret(self::PREFIX, $sessionId),
            $ttlSeconds,
            json_encode([
                'user_id' => $session->userId->toString(),
                'authenticated_at' => $session->authenticatedAt->format(self::INSTANT),
                'expires_at' => $session->expiresAt->format(self::INSTANT),
                'amr' => array_map(
                    static fn (AuthenticationMethod $method): string => $method->value,
                    $session->methods,
                ),
                'sid' => $session->sid,
                'connection' => $session->connection->value,
            ], JSON_THROW_ON_ERROR),
        );
    }

    #[\Override]
    public function find(#[\SensitiveParameter] string $sessionId): ?Session
    {
        if ($sessionId === '') {
            return null;
        }

        $raw = $this->redis->client()->get(Keys::forSecret(self::PREFIX, $sessionId));

        return is_string($raw) ? $this->decode($raw) : null;
    }

    #[\Override]
    public function extend(#[\SensitiveParameter] string $sessionId, int $ttlSeconds): void
    {
        if ($sessionId !== '') {
            // EXPIRE on a missing key does nothing, which is what the port asks for.
            $this->redis->client()->expire(Keys::forSecret(self::PREFIX, $sessionId), $ttlSeconds);
        }
    }

    #[\Override]
    public function delete(#[\SensitiveParameter] string $sessionId): void
    {
        if ($sessionId !== '') {
            $this->redis->client()->del(Keys::forSecret(self::PREFIX, $sessionId));
        }
    }

    /**
     * An entry this code cannot read is an entry that is not there: a session that
     * cannot be fully trusted is no session.
     */
    private function decode(string $raw): ?Session
    {
        try {
            $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
            if (! is_array($data)) {
                return null;
            }

            /** @var mixed $userId */
            $userId = $data['user_id'] ?? null;
            /** @var mixed $authenticatedAt */
            $authenticatedAt = $data['authenticated_at'] ?? null;
            /** @var mixed $expiresAt */
            $expiresAt = $data['expires_at'] ?? null;
            /** @var mixed $amr */
            $amr = $data['amr'] ?? null;
            /** @var mixed $sid */
            $sid = $data['sid'] ?? null;
            /** @var mixed $connection */
            $connection = $data['connection'] ?? null;

            if (
                ! is_string($userId) || ! is_string($authenticatedAt) || ! is_string($expiresAt)
                || ! is_array($amr) || ! array_is_list($amr) || ! is_string($sid) || ! is_string($connection)
            ) {
                return null;
            }

            return Session::reconstitute(
                UserId::fromString($userId),
                $this->instant($authenticatedAt),
                $this->instant($expiresAt),
                array_map(
                    static fn (mixed $method): AuthenticationMethod
                        => AuthenticationMethod::from(is_string($method) ? $method : ''),
                    $amr,
                ),
                $sid,
                ConnectionName::fromString($connection),
            );
        } catch (JsonException | InvalidValue | ValueError | Exception) {
            return null;
        }
    }

    /**
     * @throws InvalidValue
     */
    private function instant(string $value): DateTimeImmutable
    {
        $instant = DateTimeImmutable::createFromFormat(self::INSTANT, $value);
        if ($instant === false || $instant->format(self::INSTANT) !== $value) {
            throw new InvalidValue(sprintf('Not an instant in the %s format.', DateTimeInterface::RFC3339_EXTENDED));
        }

        return $instant;
    }
}
