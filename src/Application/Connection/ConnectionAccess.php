<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Connection;

use Clavia\Application\Port\IdentityProviders;
use Clavia\Application\Port\Mailer;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Connection\ConnectionStrategy;

/**
 * Which connections a sign-in may use, given the application it is for.
 *
 * The one place the three switches are combined — the connection's own `isEnabled`,
 * whether it can work at all (an external provider the deployment can build, mail for the
 * passwordless one), and the application's list or the domain flag — so the login page,
 * the password form, the email form, the provider redirect and the authorization endpoint
 * cannot disagree about what is allowed.
 */
final readonly class ConnectionAccess
{
    public function __construct(
        private ConnectionRepository $connections,
        private IdentityProviders $providers,
        private Mailer $mailer,
    ) {
    }

    /**
     * Every connection switched on and able to work, by name.
     *
     * @return list<UsableConnection>
     */
    public function usable(): array
    {
        $usable = [];
        foreach ($this->connections->all() as $connection) {
            $candidate = $this->usableAsIs($connection);
            if ($candidate !== null) {
                $usable[] = $candidate;
            }
        }

        return $usable;
    }

    /**
     * Whether `$connection` is switched on and can work — what `usable` reports to operators.
     */
    public function isUsable(Connection $connection): bool
    {
        return $this->usableAsIs($connection) !== null;
    }

    /**
     * Whether it could work were it switched on: always for a database connection, for the
     * passwordless one when the deployment sends mail, for an external one when the
     * deployment can build its provider.
     */
    public function isConfigured(Connection $connection): bool
    {
        return match ($connection->strategy) {
            ConnectionStrategy::Database => true,
            ConnectionStrategy::Passwordless => $this->mailer->canSend(),
            ConnectionStrategy::Social, ConnectionStrategy::Oidc => $this->providers->for($connection) !== null,
            // Registered and described, but nobody signs in through one before its flow exists (#126):
            // the login page offers no button that cannot work.
            ConnectionStrategy::Saml => false,
        };
    }

    /**
     * The connections a sign-in for `$client` may use.
     *
     * No application in play — a page reached directly — means every usable one: the
     * session being made is this server's own. A first-party application gets its own
     * list; a third-party one, the domain connections and nothing else.
     *
     * @return list<UsableConnection>
     */
    public function available(?Client $client): array
    {
        return array_values(array_filter(
            $this->usable(),
            static fn (UsableConnection $usable): bool => self::admits($client, $usable->connection),
        ));
    }

    public function allows(?Client $client, ConnectionName $name): bool
    {
        return array_any(
            $this->available($client),
            static fn (UsableConnection $usable): bool => $usable->connection->name->equals($name),
        );
    }

    /**
     * The pools — database connections — a sign-in for `$client` may look accounts up in.
     *
     * @return list<ConnectionName>
     */
    public function pools(?Client $client): array
    {
        $pools = [];
        foreach ($this->available($client) as $usable) {
            if ($usable->connection->isDatabase()) {
                $pools[] = $usable->connection->name;
            }
        }

        return $pools;
    }

    /**
     * The pool a person signing up for `$client` would join, or null when the application
     * offers no sign-up.
     *
     * Among the pools the application may use and that allow sign-up: the default pool when it
     * is one of them, otherwise the first by name. One form, one pool, chosen the same way
     * every time.
     */
    public function signUpPool(?Client $client): ?Connection
    {
        $open = [];
        foreach ($this->available($client) as $usable) {
            if ($usable->connection->isDatabase() && $usable->connection->allowsSignUp) {
                $open[$usable->connection->name->value] = $usable->connection;
            }
        }
        if ($open === []) {
            return null;
        }
        ksort($open, SORT_STRING);

        return $open[ConnectionName::DEFAULT_POOL] ?? array_values($open)[0];
    }

    /**
     * Whether accounts in `$pool` must prove their address before signing in with a password.
     * An unknown connection requires nothing: there is no account in it to sign in.
     */
    public function requiresVerifiedEmail(ConnectionName $pool): bool
    {
        return $this->connections->find($pool)?->requiresVerifiedEmail === true;
    }

    /** Whether this deployment can send mail: links and notices are not offered without it. */
    public function canSendMail(): bool
    {
        return $this->mailer->canSend();
    }

    /**
     * The external connection of that name with its provider, when it is switched on and
     * can work. Unknown, off, unconfigured and not external are the same null: a
     * deployment without GitHub does not answer differently from one that never heard of it.
     */
    public function external(ConnectionName $name): ?UsableConnection
    {
        $connection = $this->connections->find($name);
        $usable = $connection === null ? null : $this->usableAsIs($connection);

        return $usable?->provider === null ? null : $usable;
    }

    private function usableAsIs(Connection $connection): ?UsableConnection
    {
        if (! $connection->isEnabled) {
            return null;
        }
        if (! $connection->isExternal()) {
            return $this->isConfigured($connection) ? new UsableConnection($connection, null) : null;
        }
        $provider = $this->providers->for($connection);

        return $provider === null ? null : new UsableConnection($connection, $provider);
    }

    private static function admits(?Client $client, Connection $connection): bool
    {
        if ($client === null) {
            return true;
        }

        return $client->isFirstParty() ? $client->enables($connection->name) : $connection->isDomainConnection;
    }
}
