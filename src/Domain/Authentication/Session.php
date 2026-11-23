<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;

/**
 * A browser session: proof that a person signed in, and when.
 *
 * Two lifetimes bound it. The **absolute** one is fixed when the session is established
 * and never extended, so a stolen cookie cannot be kept alive by continuing to use it.
 * The **idle** one is a sliding window renewed on every use, so ordinary inactivity
 * ends the session; it is the storage's time-to-live, computed by {@see idleWindowAt()}
 * so that it never reaches past the absolute ceiling.
 *
 * It records the connection the person signed in through — a pool, or an external
 * provider: an application that does not enable that connection does not accept the
 * session, and its person signs in again through one it does. And it knows the
 * applications that signed in through it — each one that was issued an authorization
 * code while it was current — which are the ones told when it ends (OIDC Back-Channel
 * Logout 1.0).
 *
 * The identifier the browser holds is not part of this object: it is a secret, stored
 * only as a digest, and handed out once when the session is established.
 */
final readonly class Session
{
    /**
     * @param list<AuthenticationMethod> $methods How the sign-in was authenticated (RFC 8176).
     * @param non-empty-string           $sid     The OIDC session identifier (Back-Channel Logout
     *                                            1.0 §2.1): names the session to relying parties
     *                                            without giving them anything that opens it.
     * @param list<ClientId>             $clients The applications that signed in through it, by id.
     */
    private function __construct(
        public UserId $userId,
        public DateTimeImmutable $authenticatedAt,
        public DateTimeImmutable $expiresAt,
        public array $methods,
        public string $sid,
        public ConnectionName $connection,
        public array $clients,
    ) {
    }

    /**
     * A session starting now, for a person who has just authenticated.
     *
     * @param list<AuthenticationMethod> $methods
     * @param non-empty-string           $sid
     * @param positive-int               $absoluteLifetime Seconds until the session ends however it is used.
     */
    public static function establish(
        UserId $userId,
        array $methods,
        ConnectionName $connection,
        string $sid,
        DateTimeImmutable $now,
        int $absoluteLifetime,
    ): self {
        return self::reconstitute(
            $userId,
            $now,
            $now->modify(sprintf('+%d seconds', $absoluteLifetime)),
            $methods,
            $sid,
            $connection,
        );
    }

    /**
     * @param list<AuthenticationMethod> $methods
     * @param list<ClientId>             $clients
     *
     * @throws InvalidValue When the session would end before it began, names no method or has no sid.
     */
    public static function reconstitute(
        UserId $userId,
        DateTimeImmutable $authenticatedAt,
        DateTimeImmutable $expiresAt,
        array $methods,
        string $sid,
        ConnectionName $connection,
        array $clients = [],
    ): self {
        if ($expiresAt <= $authenticatedAt) {
            throw new InvalidValue('A session must end after it begins.');
        }

        if ($methods === []) {
            throw new InvalidValue('A session records how it was authenticated.');
        }

        if ($sid === '') {
            throw new InvalidValue('A session has a session identifier.');
        }

        $methods = array_values(array_unique($methods, SORT_REGULAR));
        $byId = [];
        foreach ($clients as $client) {
            $byId[$client->value] = $client;
        }
        ksort($byId, SORT_STRING);

        return new self($userId, $authenticatedAt, $expiresAt, $methods, $sid, $connection, array_values($byId));
    }

    /**
     * The same session, raised by one more factor (docs/design/mfa-policies.md §2): `amr`
     * gains the factor's methods and `mfa`, and `auth_time` becomes now, since the person has
     * just authenticated again. The `sid`, the connection, the applications signed in through
     * it and the absolute expiry are kept: a step-up never makes a session live longer.
     *
     * @param list<AuthenticationMethod> $added What the new factor adds to `amr`.
     */
    public function steppedUp(array $added, DateTimeImmutable $now): self
    {
        return self::reconstitute(
            $this->userId,
            $now,
            $this->expiresAt,
            AuthenticationMethod::combined($this->methods, $added),
            $this->sid,
            $this->connection,
            $this->clients,
        );
    }

    public function isExpiredAt(DateTimeImmutable $now): bool
    {
        return $this->expiresAt <= $now;
    }

    /**
     * How long the session may now sit unused: the idle lifetime, cut short by the
     * absolute ceiling. Never less than one second, which is the smallest time-to-live
     * storage can express; a session past its ceiling is ended, not renewed.
     *
     * @param positive-int $idleLifetime
     *
     * @return positive-int Seconds.
     */
    public function idleWindowAt(DateTimeImmutable $now, int $idleLifetime): int
    {
        $remaining = $this->expiresAt->getTimestamp() - $now->getTimestamp();

        return max(1, min($idleLifetime, $remaining));
    }
}
