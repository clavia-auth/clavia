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
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;
use DateTimeInterface;
use Exception;
use JsonException;
use ValueError;

/**
 * Browser sessions in Redis.
 *
 * - `session:<sha256 of the identifier>` → a JSON document, with the idle window as the
 *   key's time-to-live;
 * - `session-clients:<the same digest>` → the set of client ids that signed in through
 *   it, living exactly as long as the session: every TTL change to one is made to both;
 * - `user-sessions:<user id>` → a hash of `sid` → digest, so an account's sessions can be
 *   listed and ended. It lives as long as the longest-lived session in it; an entry whose
 *   session expired on its own is dropped the next time the hash is read.
 */
final readonly class RedisSessionStore implements SessionStore
{
    private const string PREFIX = 'session';

    private const string CLIENTS_PREFIX = 'session-clients';

    private const string USER_PREFIX = 'user-sessions';

    /** Microseconds kept: `auth_time` is reported from this, and two sign-ins in one second are two. */
    private const string INSTANT = 'Y-m-d\TH:i:s.uP';

    /**
     * KEYS[1] the account's index; ARGV[1] the sid, ARGV[2] the digest, ARGV[3] a TTL in
     * seconds. Points the sid at the digest, and lengthens the index's life to the TTL —
     * never shortens it: another session in the index may outlive this one.
     */
    private const string INDEX = <<<'LUA'
        redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
        if redis.call('TTL', KEYS[1]) < tonumber(ARGV[3]) then
            redis.call('EXPIRE', KEYS[1], ARGV[3])
        end
        return 1
        LUA;

    /**
     * KEYS[1] the account's index; ARGV[1] the sid, ARGV[2] the client id. Adds the client
     * to the session's set, with the session's own remaining life, if the session exists.
     */
    private const string RECORD_CLIENT = <<<'LUA'
        local digest = redis.call('HGET', KEYS[1], ARGV[1])
        if not digest then
            return 0
        end
        local session = 'session:' .. digest
        local ttl = redis.call('PTTL', session)
        if ttl <= 0 then
            return 0
        end
        local clients = 'session-clients:' .. digest
        redis.call('SADD', clients, ARGV[2])
        redis.call('PEXPIRE', clients, ttl)
        return 1
        LUA;

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function save(#[\SensitiveParameter] string $sessionId, Session $session, int $ttlSeconds): void
    {
        $digest = Digest::of($sessionId)->toString();
        $index = Keys::forIdentifier(self::USER_PREFIX, $session->userId->toString());
        $client = $this->redis->client();

        $client->multi();
        $client->setex(
            Keys::forIdentifier(self::PREFIX, $digest),
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
        // A new session has signed nobody in yet, whatever an identifier reused held before.
        $client->del(Keys::forIdentifier(self::CLIENTS_PREFIX, $digest));
        $client->eval(self::INDEX, [$index, $session->sid, $digest, (string) self::lifetime($session)], 1);
        $client->exec();
    }

    #[\Override]
    public function find(#[\SensitiveParameter] string $sessionId): ?Session
    {
        return $sessionId === '' ? null : $this->load(Digest::of($sessionId)->toString());
    }

    #[\Override]
    public function extend(#[\SensitiveParameter] string $sessionId, int $ttlSeconds): void
    {
        if ($sessionId === '') {
            return;
        }

        // EXPIRE on a missing key does nothing, which is what the port asks for.
        $digest = Digest::of($sessionId)->toString();
        $client = $this->redis->client();
        $client->multi();
        $client->expire(Keys::forIdentifier(self::PREFIX, $digest), $ttlSeconds);
        $client->expire(Keys::forIdentifier(self::CLIENTS_PREFIX, $digest), $ttlSeconds);
        $client->exec();
    }

    #[\Override]
    public function delete(#[\SensitiveParameter] string $sessionId): void
    {
        if ($sessionId === '') {
            return;
        }

        $digest = Digest::of($sessionId)->toString();
        $session = $this->load($digest);
        $this->drop($digest, $session);
    }

    #[\Override]
    public function recordClient(UserId $userId, string $sid, ClientId $client): void
    {
        if ($sid === '') {
            return;
        }

        $this->redis->client()->eval(
            self::RECORD_CLIENT,
            [Keys::forIdentifier(self::USER_PREFIX, $userId->toString()), $sid, $client->value],
            1,
        );
    }

    #[\Override]
    public function ofUser(UserId $userId): array
    {
        return array_map(
            static fn (array $entry): Session => $entry['session'],
            $this->indexed($userId),
        );
    }

    #[\Override]
    public function endOfUser(UserId $userId, ?string $sid = null): array
    {
        $ended = [];
        foreach ($this->indexed($userId) as ['digest' => $digest, 'session' => $session]) {
            if ($sid === null || $session->sid === $sid) {
                $this->drop($digest, $session);
                $ended[] = $session;
            }
        }

        return $ended;
    }

    /**
     * The account's current sessions with their digests, oldest first. Entries whose
     * session is gone, or now holds somebody else's, are dropped from the index.
     *
     * @return list<array{digest: string, session: Session}>
     */
    private function indexed(UserId $userId): array
    {
        $index = Keys::forIdentifier(self::USER_PREFIX, $userId->toString());
        $client = $this->redis->client();
        /** @var array<string, string>|false $entries */
        $entries = $client->hGetAll($index);
        if (! is_array($entries)) {
            return [];
        }

        $found = [];
        foreach ($entries as $sid => $digest) {
            $session = $this->load($digest);
            if ($session === null || $session->sid !== $sid || ! $session->userId->equals($userId)) {
                $client->hDel($index, $sid);
                continue;
            }
            $found[] = ['digest' => $digest, 'session' => $session];
        }
        usort(
            $found,
            /**
             * @param array{digest: string, session: Session} $a
             * @param array{digest: string, session: Session} $b
             */
            static fn (array $a, array $b): int => $a['session']->authenticatedAt <=> $b['session']->authenticatedAt,
        );

        return $found;
    }

    private function load(string $digest): ?Session
    {
        $client = $this->redis->client();
        $raw = $client->get(Keys::forIdentifier(self::PREFIX, $digest));
        if (! is_string($raw)) {
            return null;
        }

        /** @var list<string>|false $clients */
        $clients = $client->sMembers(Keys::forIdentifier(self::CLIENTS_PREFIX, $digest));

        return $this->decode($raw, is_array($clients) ? $clients : []);
    }

    /** Delete a session's keys and the index entry that points at it. */
    private function drop(string $digest, ?Session $session): void
    {
        $client = $this->redis->client();
        $client->multi();
        $client->del(Keys::forIdentifier(self::PREFIX, $digest), Keys::forIdentifier(self::CLIENTS_PREFIX, $digest));
        if ($session !== null) {
            $client->hDel(Keys::forIdentifier(self::USER_PREFIX, $session->userId->toString()), $session->sid);
        }
        $client->exec();
    }

    /**
     * The session's whole absolute lifetime: no session in the index outlives the index.
     * Measured from the session itself rather than the wall clock, so it is right whatever
     * clock the session was made with.
     *
     * @return positive-int Seconds.
     */
    private static function lifetime(Session $session): int
    {
        return max(1, $session->expiresAt->getTimestamp() - $session->authenticatedAt->getTimestamp());
    }

    /**
     * An entry this code cannot read is an entry that is not there: a session that
     * cannot be fully trusted is no session.
     */
    /**
     * @param list<string> $clients
     */
    private function decode(string $raw, array $clients): ?Session
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
                array_map(ClientId::fromString(...), $clients),
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
