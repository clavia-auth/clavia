<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\IdentityProvider;

use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\EncryptionUnavailable;
use Clavia\Application\Port\IdentityProvider;
use Clavia\Application\Port\IdentityProviders;
use Clavia\Application\Port\SecretCipher;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionStrategy;
use Clavia\Domain\Connection\OidcSettings;
use Psr\Log\LoggerInterface;

/**
 * The provider behind each external connection.
 *
 * A social connection names one of the providers the code implements; the composition
 * root builds those the deployment configured, from the `CLAVIA_<PROVIDER>_CLIENT_ID` /
 * `_CLIENT_SECRET` pairs. An OIDC connection carries its own settings; its client secret
 * is decrypted here, and only here.
 */
final readonly class ConnectionIdentityProviders implements IdentityProviders
{
    /** @var array<string, IdentityProvider> */
    private array $social;

    /**
     * @param list<IdentityProvider> $social The configured social providers.
     */
    public function __construct(
        array $social,
        private SecretCipher $cipher,
        private ProviderHttp $http,
        private IdTokenVerifier $idTokens,
        private OutboundUrlPolicy $outbound,
        private LoggerInterface $logger,
    ) {
        $byName = [];
        foreach ($social as $provider) {
            $byName[$provider->name()->value] = $provider;
        }
        $this->social = $byName;
    }

    #[\Override]
    public function for(Connection $connection): ?IdentityProvider
    {
        return match ($connection->strategy) {
            // A SAML provider is no IdentityProvider: it signs people in through its own flow.
            ConnectionStrategy::Database, ConnectionStrategy::Passwordless, ConnectionStrategy::Saml => null,
            ConnectionStrategy::Social => $this->social[$connection->name->value] ?? null,
            ConnectionStrategy::Oidc => $this->openIdProvider($connection),
        };
    }

    private function openIdProvider(Connection $connection): ?IdentityProvider
    {
        $settings = $connection->oidc;
        if ($settings === null) {
            return null;
        }

        try {
            $secret = $this->cipher->decrypt(
                $settings->encryptedClientSecret,
                OidcSettings::secretContext($connection->name),
            );
        } catch (DecryptionFailed | EncryptionUnavailable $failure) {
            // The key changed, or the row was tampered with: a connection that cannot work.
            $this->logger->warning('The client secret of the connection {connection} cannot be decrypted: {reason}', [
                'connection' => $connection->name->value,
                'reason' => $failure::class,
            ]);

            return null;
        }
        if ($secret === '') {
            return null;
        }

        return new OidcIdentityProvider(
            $connection->name,
            $settings,
            $secret,
            $this->http,
            $this->idTokens,
            $this->outbound,
        );
    }
}
