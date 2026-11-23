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
use Clavia\Application\Clients\Registration\RegisterClientDynamically;
use Clavia\Application\Clients\Registration\RegistrationMetadata;
use Clavia\Application\Port\AttemptCounter;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\TransactionManager;
use Clavia\Configuration\Settings;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Client\Registration\InitialAccessTokenRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class RegisterClientDynamicallyFactory
{
    public function __invoke(ContainerInterface $container): RegisterClientDynamically
    {
        /** @var InitialAccessTokenRepository $initialAccessTokens */
        $initialAccessTokens = $container->get(InitialAccessTokenRepository::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var ClientRegistrationRepository $registrations */
        $registrations = $container->get(ClientRegistrationRepository::class);
        /** @var RegistrationMetadata $metadata */
        $metadata = $container->get(RegistrationMetadata::class);
        /** @var PasswordHasher $hasher */
        $hasher = $container->get(PasswordHasher::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var AttemptCounter $counter */
        $counter = $container->get(AttemptCounter::class);
        /** @var AuditContext $audit */
        $audit = $container->get(AuditContext::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $limit = $settings->clientRegistrationMaxPerAddress;
        $window = $settings->clientRegistrationWindow;
        assert($limit > 0 && $window > 0);

        return new RegisterClientDynamically(
            $initialAccessTokens,
            $clients,
            $registrations,
            $metadata,
            $hasher,
            $secrets,
            $clock,
            $transactions,
            $counter,
            $audit,
            $events,
            $limit,
            $window,
        );
    }
}
