<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Development;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\Ownership;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;
use Clavia\Domain\Shared\Url;
use LogicException;

/**
 * Registers the management dashboard (`frontend/`) as what it is: an ordinary public
 * client using the code flow with PKCE, and refresh tokens. It holds nothing of its own; what a signed-in
 * operator may do is whatever they hold on the Management API.
 *
 * Idempotent by name. A rerun brings its URIs up to date — they follow the management
 * host, which a developer may have changed since.
 */
final readonly class SeedDashboardClient
{
    public const string CLIENT_NAME = 'Clavia dashboard';

    /** The prefix the dashboard is served under on `management.{domain}`: Vite's `base`, and Caddy's route. */
    public const string PATH = '/dashboard';

    /** The code flow, and rotating refresh tokens so a session outlives one access token. */
    private const array GRANT_TYPES = [GrantType::AuthorizationCode, GrantType::RefreshToken];

    public function __construct(
        private ClientRepository $clients,
        private SecretGenerator $secrets,
        private Clock $clock,
        private bool $isDevelopment,
    ) {
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

        $base = 'https://' . $managementHost . self::PATH;
        $callback = Url::fromString($base . '/callback');
        $signedOut = Url::fromString($base . '/signed-out');

        $existing = $this->clients->findByName(self::CLIENT_NAME);
        $client = $existing === null
            ? Client::register(
                ClientId::generate($this->secrets, Ownership::FirstParty),
                self::CLIENT_NAME,
                ClientType::Public,
                ClientAuthMethod::None,
                null,
                [$callback],
                self::GRANT_TYPES,
                [ResponseType::Code],
                $this->clock->now(),
                [$signedOut],
            )
            : $existing->reconfigure(
                self::CLIENT_NAME,
                [$callback],
                self::GRANT_TYPES,
                [ResponseType::Code],
                ClientAuthMethod::None,
                [$signedOut],
            );
        $this->clients->save($client);

        return new SeededDashboard($client->id, $existing === null);
    }
}
