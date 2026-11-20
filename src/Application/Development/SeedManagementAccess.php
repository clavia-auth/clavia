<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Development;

use Clavia\Application\Clients\RegisterMachineClient;
use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Client\ClientRepository;
use LogicException;

/**
 * The second half of `seed-dev`: the Management API, and a machine client granted every
 * scope on it, so a fresh checkout can call `/api/v1/*` straight away rather than merely
 * ask for a token it would be refused.
 *
 * The machine client's secret is a fixed, published value — printable on every rerun,
 * which a generated one could not be — and that is what makes this development-only.
 * Idempotent: the client is found by name, its grant rewritten to every scope the API
 * defines now.
 */
final readonly class SeedManagementAccess
{
    public const string CLIENT_NAME = 'Clavia development machine client';

    public const string CLIENT_SECRET = 'dev-m2m-secret-for-local-development-only';

    public function __construct(
        private ClientRepository $clients,
        private RegisterManagementApi $registerManagementApi,
        private RegisterMachineClient $registerMachineClient,
        private GrantClientAccess $grantClientAccess,
        private TransactionManager $transactions,
        private bool $isDevelopment,
    ) {
    }

    /**
     * @throws LogicException When this is not a development deployment.
     */
    public function __invoke(): SeededManagementAccess
    {
        if (! $this->isDevelopment) {
            throw new LogicException('Refusing to seed development data outside a development deployment.');
        }

        return $this->transactions->transactional(function (): SeededManagementAccess {
            $api = ($this->registerManagementApi)();

            $client = $this->clients->findByName(self::CLIENT_NAME);
            $created = $client === null;
            $client ??= ($this->registerMachineClient)(self::CLIENT_NAME, self::CLIENT_SECRET)->client;

            $grant = ($this->grantClientAccess)($client->id, $api->identifier);

            return new SeededManagementAccess($api->identifier, $client->id, $created, $grant->scopes);
        });
    }
}
