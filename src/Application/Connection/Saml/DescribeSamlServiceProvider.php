<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Connection\Saml;

use Clavia\Application\Port\Saml\ServiceProviderDescription;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Application\Port\Saml\SamlServiceProvider;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Connection\Saml\ServiceProviderKey;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `GET /auth/saml/{connection}/metadata` (docs/design/saml-connections.md §5.4): this server's
 * `EntityDescriptor` for one enabled SAML connection, with the current and next certificates of each
 * usage, so an identity provider picks up a new key before it is used. Nothing secret in it.
 */
final readonly class DescribeSamlServiceProvider
{
    public function __construct(
        private ConnectionRepository $connections,
        private ServiceProviderKeys $keys,
        private SamlServiceProvider $saml,
        private SamlServiceProviderEndpoints $endpoints,
    ) {
    }

    /** The metadata document; null when no enabled SAML connection has that name. */
    public function __invoke(string $name): ?string
    {
        try {
            $connection = $this->connections->find(ConnectionName::fromString($name));
        } catch (InvalidValue) {
            return null;
        }
        if ($connection === null || $connection->saml === null || ! $connection->isEnabled) {
            return null;
        }
        $published = $this->keys->certificates()->published()->keys;
        $certificates = static fn (ServiceProviderKeyUsage $usage): array => array_values(array_map(
            static fn (ServiceProviderKey $key): string => $key->certificate,
            array_filter($published, static fn (ServiceProviderKey $key): bool => $key->usage === $usage),
        ));

        return $this->saml->serviceProviderMetadata(new ServiceProviderDescription(
            $this->endpoints->entityId($connection->name),
            $this->endpoints->assertionConsumerService($connection->name),
            $connection->saml->options->nameIdFormat,
            $certificates(ServiceProviderKeyUsage::Signing),
            $certificates(ServiceProviderKeyUsage::Encryption),
            $connection->saml->options->signRequests,
        ));
    }
}
