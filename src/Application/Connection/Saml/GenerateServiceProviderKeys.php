<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Connection\Saml;

use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Connection\Saml\Event\ServiceProviderKeysGenerated;
use Clavia\Domain\Connection\Saml\ServiceProviderKeySet;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use Clavia\Domain\Shared\Clock;

/**
 * `clavia saml-keys:generate` (§5.1): the first pair, current at once. Refused when one exists, so
 * it never replaces keys an identity provider already pins. Nothing makes keys on first use: a SAML
 * sign-in without them is unsigned and unencrypted.
 */
final readonly class GenerateServiceProviderKeys
{
    public function __construct(
        private ServiceProviderKeyStore $keys,
        private TransactionManager $transactions,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /** @throws ServiceProviderKeysExist */
    public function __invoke(): ServiceProviderKeySet
    {
        /** @var ServiceProviderKeySet */
        return $this->transactions->transactional(function (): ServiceProviderKeySet {
            if ($this->keys->lockAll()->current(ServiceProviderKeyUsage::Signing) !== null) {
                throw new ServiceProviderKeysExist('A current pair of service provider keys exists: rotate it.');
            }
            $pair = $this->keys->createPair(ServiceProviderKeyStatus::Current, $this->clock->now());
            $this->events->dispatch(new ServiceProviderKeysGenerated($pair['signing'], $pair['encryption']));

            return $this->keys->all();
        });
    }
}
