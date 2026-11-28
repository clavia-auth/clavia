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
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authorization\IdentityFeedOutbox;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientLogoRepository;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Client\Registration\InitialAccessTokenRepository;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\Jobs\UserJobRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\Provisioning\ProvisionedAccountRepository;
use Clavia\Domain\Provisioning\ProvisioningTokenRepository;
use Clavia\Domain\Provisioning\ScimGroupRepository;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Webhook\WebhookEndpointRepository;
use ClaviaTest\Support\Contract\AuthorizationCodeRepositoryContract;
use ClaviaTest\Support\Contract\ClientLogoRepositoryContract;
use ClaviaTest\Support\Contract\ClientRegistrationRepositoryContract;
use ClaviaTest\Support\Contract\ClientRepositoryContract;
use ClaviaTest\Support\Contract\ConnectionRepositoryContract;
use ClaviaTest\Support\Contract\ConsentRepositoryContract;
use ClaviaTest\Support\Contract\ExternalIdentityRepositoryContract;
use ClaviaTest\Support\Contract\IdentityFeedOutboxContract;
use ClaviaTest\Support\Contract\InitialAccessTokenRepositoryContract;
use ClaviaTest\Support\Contract\MfaRepositoriesContract;
use ClaviaTest\Support\Contract\PasskeyRepositoryContract;
use ClaviaTest\Support\Contract\ProvisionedAccountRepositoryContract;
use ClaviaTest\Support\Contract\ProvisioningTokenRepositoryContract;
use ClaviaTest\Support\Contract\ResourceServerRepositoryContract;
use ClaviaTest\Support\Contract\RoleRepositoryContract;
use ClaviaTest\Support\Contract\ScimGroupRepositoryContract;
use ClaviaTest\Support\Contract\UserJobRepositoryContract;
use ClaviaTest\Support\Contract\UserRepositoryContract;
use ClaviaTest\Support\Contract\WebhookEndpointRepositoryContract;
use ClaviaTest\Support\Fake\InMemoryAuthorizationCodeRepository;
use ClaviaTest\Support\Fake\InMemoryClientGrantRepository;
use ClaviaTest\Support\Fake\InMemoryClientLogoRepository;
use ClaviaTest\Support\Fake\InMemoryClientRegistrationRepository;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryConnectionRepository;
use ClaviaTest\Support\Fake\InMemoryConsentRepository;
use ClaviaTest\Support\Fake\InMemoryExternalIdentityRepository;
use ClaviaTest\Support\Fake\InMemoryIdentityFeedOutbox;
use ClaviaTest\Support\Fake\InMemoryInitialAccessTokenRepository;
use ClaviaTest\Support\Fake\InMemoryMfaFactorRepository;
use ClaviaTest\Support\Fake\InMemoryPasskeyRepository;
use ClaviaTest\Support\Fake\InMemoryProvisionedAccountRepository;
use ClaviaTest\Support\Fake\InMemoryProvisioningTokenRepository;
use ClaviaTest\Support\Fake\InMemoryRecoveryCodeRepository;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryRoleRepository;
use ClaviaTest\Support\Fake\InMemoryScimGroupRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserJobRepository;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\InMemoryWebhookEndpointRepository;
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
    use ClientLogoRepositoryContract;
    use AuthorizationCodeRepositoryContract;
    use ResourceServerRepositoryContract;
    use IdentityFeedOutboxContract;
    use MfaRepositoriesContract;
    use PasskeyRepositoryContract;
    use ExternalIdentityRepositoryContract;
    use RoleRepositoryContract;
    use ConsentRepositoryContract;
    use ConnectionRepositoryContract;
    use InitialAccessTokenRepositoryContract;
    use ProvisioningTokenRepositoryContract;
    use ProvisionedAccountRepositoryContract;
    use ScimGroupRepositoryContract;
    use WebhookEndpointRepositoryContract;
    use ClientRegistrationRepositoryContract;
    use UserJobRepositoryContract;

    private ?InMemoryClientLogoRepository $clientLogos = null;

    private InMemoryRoleRepository $roles;
    private InMemoryUserRepository $users;
    private InMemoryClientRepository $clients;
    private InMemoryTransactionManager $transactions;
    private InMemoryAuthorizationCodeRepository $codes;
    private InMemoryResourceServerRepository $resourceServers;
    private InMemoryIdentityFeedOutbox $feed;
    private InMemoryClientGrantRepository $clientGrants;
    private InMemoryMfaFactorRepository $factors;
    private InMemoryRecoveryCodeRepository $recoveryCodes;
    private InMemoryPasskeyRepository $passkeys;
    private InMemoryExternalIdentityRepository $identities;
    private InMemoryConsentRepository $consents;
    private InMemoryConnectionRepository $connections;
    private InMemoryInitialAccessTokenRepository $initialAccessTokens;

    private InMemoryProvisioningTokenRepository $provisioningTokens;

    private ?InMemoryProvisionedAccountRepository $provisionedAccounts = null;

    private ?InMemoryScimGroupRepository $scimGroups = null;
    private InMemoryWebhookEndpointRepository $webhookEndpoints;
    private InMemoryClientRegistrationRepository $clientRegistrations;
    private ?InMemoryUserJobRepository $userJobs = null;

    #[\Override]
    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
        $this->clients = new InMemoryClientRepository();
        $this->connections = new InMemoryConnectionRepository($this->clients);
        $this->transactions = new InMemoryTransactionManager();
        $this->codes = new InMemoryAuthorizationCodeRepository($this->transactions);
        $this->clientGrants = new InMemoryClientGrantRepository();
        $this->feed = new InMemoryIdentityFeedOutbox();
        $this->resourceServers = new InMemoryResourceServerRepository($this->clientGrants, $this->feed);
        $this->factors = new InMemoryMfaFactorRepository($this->transactions);
        $this->recoveryCodes = new InMemoryRecoveryCodeRepository();
        $this->passkeys = new InMemoryPasskeyRepository();
        $this->identities = new InMemoryExternalIdentityRepository();
        $this->roles = new InMemoryRoleRepository($this->resourceServers, $this->users);
        $this->consents = new InMemoryConsentRepository($this->users, $this->clients, $this->resourceServers);
        $this->initialAccessTokens = new InMemoryInitialAccessTokenRepository();
        $this->provisioningTokens = new InMemoryProvisioningTokenRepository();
        $this->webhookEndpoints = new InMemoryWebhookEndpointRepository();
        $this->clientRegistrations = new InMemoryClientRegistrationRepository($this->clients);
    }

    #[\Override]
    protected function connections(): ConnectionRepository
    {
        return $this->connections;
    }

    #[\Override]
    protected function consents(): ConsentRepository
    {
        return $this->consents;
    }

    #[\Override]
    protected function initialAccessTokens(): InitialAccessTokenRepository
    {
        return $this->initialAccessTokens;
    }

    #[\Override]
    protected function provisioningTokens(): ProvisioningTokenRepository
    {
        return $this->provisioningTokens;
    }

    #[\Override]
    protected function provisionedAccounts(): ProvisionedAccountRepository
    {
        return $this->provisionedAccounts ??= new InMemoryProvisionedAccountRepository($this->users());
    }

    #[\Override]
    protected function scimGroups(): ScimGroupRepository
    {
        return $this->scimGroups ??= new InMemoryScimGroupRepository($this->users());
    }

    #[\Override]
    protected function clientRegistrations(): ClientRegistrationRepository
    {
        return $this->clientRegistrations;
    }

    #[\Override]
    protected function userJobs(): UserJobRepository
    {
        return $this->userJobs ??= new InMemoryUserJobRepository();
    }

    #[\Override]
    protected function roles(): RoleRepository
    {
        return $this->roles;
    }

    #[\Override]
    protected function users(): UserRepository
    {
        return $this->users;
    }

    #[\Override]
    protected function identities(): ExternalIdentityRepository
    {
        return $this->identities;
    }

    #[\Override]
    protected function passkeys(): PasskeyRepository
    {
        return $this->passkeys;
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
    protected function clientLogos(): ClientLogoRepository
    {
        return $this->clientLogos ??= new InMemoryClientLogoRepository();
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
    protected function identityFeedOutbox(): IdentityFeedOutbox
    {
        return $this->feed;
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

    #[\Override]
    protected function webhookEndpoints(): WebhookEndpointRepository
    {
        return $this->webhookEndpoints;
    }
}
