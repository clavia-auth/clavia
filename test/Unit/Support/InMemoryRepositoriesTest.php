<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use ClaviaTest\Support\Contract\AuthorizationCodeRepositoryContract;
use ClaviaTest\Support\Contract\ClientRepositoryContract;
use ClaviaTest\Support\Contract\MfaRepositoriesContract;
use ClaviaTest\Support\Contract\ResourceServerRepositoryContract;
use ClaviaTest\Support\Contract\UserRepositoryContract;
use ClaviaTest\Support\Fake\InMemoryAuthorizationCodeRepository;
use ClaviaTest\Support\Fake\InMemoryClientGrantRepository;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryMfaFactorRepository;
use ClaviaTest\Support\Fake\InMemoryRecoveryCodeRepository;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

/**
 * The in-memory repositories honour the same contracts as the PostgreSQL ones, which is
 * what makes a unit test written against them worth anything.
 */
final class InMemoryRepositoriesTest extends TestCase
{
    use UserRepositoryContract;
    use ClientRepositoryContract;
    use AuthorizationCodeRepositoryContract;
    use ResourceServerRepositoryContract;
    use MfaRepositoriesContract;

    private InMemoryUserRepository $users;
    private InMemoryClientRepository $clients;
    private InMemoryTransactionManager $transactions;
    private InMemoryAuthorizationCodeRepository $codes;
    private InMemoryResourceServerRepository $resourceServers;
    private InMemoryClientGrantRepository $clientGrants;
    private InMemoryMfaFactorRepository $factors;
    private InMemoryRecoveryCodeRepository $recoveryCodes;

    #[\Override]
    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
        $this->clients = new InMemoryClientRepository();
        $this->transactions = new InMemoryTransactionManager();
        $this->codes = new InMemoryAuthorizationCodeRepository($this->transactions);
        $this->clientGrants = new InMemoryClientGrantRepository();
        $this->resourceServers = new InMemoryResourceServerRepository($this->clientGrants);
        $this->factors = new InMemoryMfaFactorRepository($this->transactions);
        $this->recoveryCodes = new InMemoryRecoveryCodeRepository();
    }

    #[\Override]
    protected function users(): UserRepository
    {
        return $this->users;
    }

    #[\Override]
    protected function factors(): MfaFactorRepository
    {
        return $this->factors;
    }

    #[\Override]
    protected function recoveryCodes(): RecoveryCodeRepository
    {
        return $this->recoveryCodes;
    }

    #[\Override]
    protected function clients(): ClientRepository
    {
        return $this->clients;
    }

    #[\Override]
    protected function codes(): AuthorizationCodeRepository
    {
        return $this->codes;
    }

    #[\Override]
    protected function transactional(callable $work): mixed
    {
        return $this->transactions->transactional($work);
    }

    #[\Override]
    protected function anOwner(): array
    {
        return [ClientId::fromString('spa'), UserId::generate(new SeededRandomSource(7))];
    }

    #[\Override]
    protected function resourceServers(): ResourceServerRepository
    {
        return $this->resourceServers;
    }

    #[\Override]
    protected function clientGrants(): ClientGrantRepository
    {
        return $this->clientGrants;
    }

    #[\Override]
    protected function aClient(string $clientId): ClientId
    {
        return ClientId::fromString($clientId);
    }
}
