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
use Clavia\Application\Management\NotFound;
use Clavia\Application\Management\Provisioning\AssignRole;
use Clavia\Application\Management\Provisioning\EnsureRole;
use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Client\ClientRepository;
use LogicException;

/**
 * The second half of `seed-dev`: the Management API; a machine client granted every scope
 * on it, so a fresh checkout can call `/api/v1/*` straight away rather than merely ask for
 * a token it would be refused; and an Administrator role holding every management
 * permission, given to the development user — without it, the dashboard would let them
 * sign in and then refuse them a token, roles being always on for the Management API.
 *
 * The machine client's secret is a fixed, published value — printable on every rerun,
 * which a generated one could not be — and that is what makes this development-only.
 * Idempotent: the client is found by name, its grant rewritten to every scope the API
 * defines now; the role is found by name and given what it lacks.
 */
final readonly class SeedManagementAccess
{
    public const string CLIENT_NAME = 'Clavia development machine client';

    public const string CLIENT_SECRET = 'dev-m2m-secret-for-local-development-only';

    public const string ADMINISTRATOR_ROLE = 'Administrator';

    public function __construct(
        private ClientRepository $clients,
        private RegisterManagementApi $registerManagementApi,
        private RegisterMachineClient $registerMachineClient,
        private GrantClientAccess $grantClientAccess,
        private EnsureRole $ensureRole,
        private AssignRole $assignRole,
        private TransactionManager $transactions,
        private bool $isDevelopment,
    ) {
    }

    /**
     * @param string $administrator The address of the account given the Administrator role.
     *
     * @throws LogicException When this is not a development deployment.
     * @throws NotFound       When there is no account with the address.
     */
    public function __invoke(string $administrator): SeededManagementAccess
    {
        if (! $this->isDevelopment) {
            throw new LogicException('Refusing to seed development data outside a development deployment.');
        }

        return $this->transactions->transactional(function () use ($administrator): SeededManagementAccess {
            $api = ($this->registerManagementApi)();

            $client = $this->clients->findByName(self::CLIENT_NAME);
            $created = $client === null;
            $client ??= ($this->registerMachineClient)(self::CLIENT_NAME, self::CLIENT_SECRET)->client;

            $grant = ($this->grantClientAccess)($client->id, $api->identifier);

            ($this->ensureRole)(
                self::ADMINISTRATOR_ROLE,
                'Full access to the Clavia Management API.',
                $api->identifier,
            );
            ($this->assignRole)(self::ADMINISTRATOR_ROLE, $administrator);

            return new SeededManagementAccess($api->identifier, $client->id, $created, $grant->scopes);
        });
    }
}
