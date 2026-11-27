<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Development;

use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Client\BackChannelLogout;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\InitiateLoginUri;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;
use LogicException;

/**
 * Registers the management dashboard (the `clavia-dashboard` repository) as what it is: a
 * confidential, first-party client — a backend for frontend that redeems codes and keeps
 * tokens server-side — using the code flow with PKCE, refresh tokens, RP-Initiated Logout
 * and back-channel logout. It holds nothing of its own; what a signed-in operator may do is
 * whatever their roles grant on the Management API.
 *
 * Its id and secret are fixed development values, like the development machine client's,
 * so the dashboard's `.env.example` works as it is. A rerun brings its URIs up to date —
 * they follow the management host, which a developer may have changed since — and keeps
 * the connections it enables. A public dashboard client an earlier seed registered under a
 * generated id is removed.
 */
final readonly class SeedDashboardClient
{
    public const string CLIENT_ID = 'clavia-dashboard';

    public const string CLIENT_NAME = 'Clavia dashboard';

    /** A development secret, printed by `seed-dev`; a real deployment registers its own. */
    public const string CLIENT_SECRET = 'dev-dashboard-secret-for-local-development-only';

    /** The prefix the dashboard is served under on `management.{domain}`: its `basePath`, and Caddy's route. */
    public const string PATH = '/dashboard';

    /** The code flow, and rotating refresh tokens so a session outlives one access token. */
    private const array GRANT_TYPES = [GrantType::AuthorizationCode, GrantType::RefreshToken];

    public function __construct(
        private ClientRepository $clients,
        private PasswordHasher $hasher,
        private Clock $clock,
        private bool $isDevelopment,
    ) {
    }

    /** The dashboard's address on `$managementHost`: `https://management.{domain}/dashboard`. */
    public static function url(string $managementHost): string
    {
        return 'https://' . $managementHost . self::PATH;
    }

    /**
     * @param string $managementHost `management.{domain}`.
     *
     * @throws LogicException When this is not a development deployment.
     * @throws InvalidValue   When the host cannot make a URL.
     */
    public function __invoke(string $managementHost): SeededDashboard
    {
        if (! $this->isDevelopment) {
            throw new LogicException('Refusing to seed development data outside a development deployment.');
        }

        $base = self::url($managementHost);
        $id = ClientId::fromString(self::CLIENT_ID);

        $earlier = $this->clients->findByName(self::CLIENT_NAME);
        if ($earlier !== null && ! $earlier->id->equals($id)) {
            // The single-page dashboard this one replaces: a public client under a generated id.
            $this->clients->delete($earlier->id);
        }

        $existing = $this->clients->find($id);
        $this->clients->save(Client::register(
            $id,
            self::CLIENT_NAME,
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretBasic,
            $this->hasher->hash(self::CLIENT_SECRET),
            [Url::fromString($base . '/auth/callback')],
            self::GRANT_TYPES,
            [ResponseType::Code],
            $existing?->createdAt ?? $this->clock->now(),
            [Url::fromString($base . '/signed-out')],
            // Operators sign in with a password; other connections are enabled through the API.
            $existing?->connections ?? [ConnectionName::defaultPool()],
            new BackChannelLogout(Url::fromString($base . '/auth/backchannel-logout'), sessionRequired: true),
            // Where a sign-in that outlived its request sends the operator back to (#219): a GET there
            // starts a new attempt.
            initiateLoginUri: InitiateLoginUri::fromString($base . '/auth/sign-in'),
        ));

        return new SeededDashboard($id, $existing === null);
    }
}
