<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Clients\Registration\RegisteredClients;
use Clavia\Application\Clients\Registration\RegistrationMetadata;
use Clavia\Application\Clients\Registration\UpdateClientConfiguration;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class UpdateClientConfigurationFactory
{
    public function __invoke(ContainerInterface $container): UpdateClientConfiguration
    {
        /** @var RegisteredClients $registered */
        $registered = $container->get(RegisteredClients::class);
        /** @var RegistrationMetadata $metadata */
        $metadata = $container->get(RegistrationMetadata::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var ClientRegistrationRepository $registrations */
        $registrations = $container->get(ClientRegistrationRepository::class);
        /** @var PasswordHasher $hasher */
        $hasher = $container->get(PasswordHasher::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var AuditContext $audit */
        $audit = $container->get(AuditContext::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new UpdateClientConfiguration(
            $registered,
            $metadata,
            $clients,
            $registrations,
            $hasher,
            $secrets,
            $transactions,
            $audit,
            $events,
        );
    }
}
