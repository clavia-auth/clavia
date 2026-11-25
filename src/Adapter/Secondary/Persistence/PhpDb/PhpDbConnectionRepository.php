<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Connection\ConnectionStrategy;
use Clavia\Domain\Connection\OidcSettings;
use Clavia\Domain\Connection\Saml\SamlCertificate;
use Clavia\Domain\Connection\Saml\SamlOptions;
use Clavia\Domain\Connection\Saml\SamlSettings;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\Url;
use Throwable;

/**
 * Connections in `connections`, the built-in ones seeded by the schema.
 *
 * @psalm-type ConnectionRow = array{name: string, display_name: string, strategy: string, is_enabled: bool,
 *     is_domain_connection: bool, oidc_issuer: string|null, oidc_client_id: string|null,
 *     oidc_client_secret_encrypted: string|null, oidc_scope: string|null,
 *     oidc_authorization_endpoint: string|null, oidc_token_endpoint: string|null, oidc_jwks_uri: string|null,
 *     created_at: string, allow_sign_up: bool, require_verified_email: bool, saml_entity_id: string|null,
 *     saml_sso_url: string|null, saml_certificates: string|null, saml_metadata_url: string|null,
 *     saml_options: string|null}
 */
final readonly class PhpDbConnectionRepository implements ConnectionRepository
{
    private const string COLUMNS = 'name, display_name, strategy, is_enabled, is_domain_connection, oidc_issuer, '
        . 'oidc_client_id, oidc_client_secret_encrypted, oidc_scope, oidc_authorization_endpoint, '
        . 'oidc_token_endpoint, oidc_jwks_uri, created_at, allow_sign_up, require_verified_email, saml_entity_id, '
        . 'saml_sso_url, saml_certificates::text AS saml_certificates, saml_metadata_url, '
        . 'saml_options::text AS saml_options';

    private const string WRITTEN = 'name, display_name, strategy, is_enabled, is_domain_connection, oidc_issuer, '
        . 'oidc_client_id, oidc_client_secret_encrypted, oidc_scope, oidc_authorization_endpoint, '
        . 'oidc_token_endpoint, oidc_jwks_uri, created_at, allow_sign_up, require_verified_email, saml_entity_id, '
        . 'saml_sso_url, saml_certificates, saml_metadata_url, saml_options';

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function find(ConnectionName $name): ?Connection
    {
        /** @var ConnectionRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM connections WHERE name = :name',
            ['name' => $name->value],
        );

        return $row === null ? null : self::hydrate($row);
    }

    #[\Override]
    public function all(): array
    {
        /** @var list<ConnectionRow> $rows */
        $rows = $this->database->fetchAll('SELECT ' . self::COLUMNS . ' FROM connections ORDER BY name');

        return array_map(self::hydrate(...), $rows);
    }

    #[\Override]
    public function add(Connection $connection): void
    {
        try {
            $this->database->execute(
                'INSERT INTO connections (' . self::WRITTEN . ') VALUES (:name, :display_name, :strategy,'
                . ' :is_enabled, :is_domain_connection, :oidc_issuer, :oidc_client_id,'
                . ' :oidc_client_secret_encrypted, :oidc_scope, :oidc_authorization_endpoint,'
                . ' :oidc_token_endpoint, :oidc_jwks_uri, :created_at, :allow_sign_up, :require_verified_email,'
                . ' :saml_entity_id, :saml_sso_url, CAST(:saml_certificates AS jsonb), :saml_metadata_url,'
                . ' CAST(:saml_options AS jsonb))',
                self::parameters($connection),
            );
        } catch (Throwable $failure) {
            throw Constraint::isUniqueViolation($failure, 'connections_pkey')
                ? new AlreadyExists(
                    sprintf("A connection named '%s' already exists.", $connection->name->value),
                    0,
                    $failure,
                )
                : $failure;
        }
    }

    #[\Override]
    public function save(Connection $connection): void
    {
        $parameters = self::parameters($connection);
        unset($parameters['strategy'], $parameters['created_at']);
        $this->database->execute(
            <<<'SQL'
                UPDATE connections SET
                    display_name = :display_name,
                    is_enabled = :is_enabled,
                    is_domain_connection = :is_domain_connection,
                    oidc_issuer = :oidc_issuer,
                    oidc_client_id = :oidc_client_id,
                    oidc_client_secret_encrypted = :oidc_client_secret_encrypted,
                    oidc_scope = :oidc_scope,
                    oidc_authorization_endpoint = :oidc_authorization_endpoint,
                    oidc_token_endpoint = :oidc_token_endpoint,
                    oidc_jwks_uri = :oidc_jwks_uri,
                    allow_sign_up = :allow_sign_up,
                    require_verified_email = :require_verified_email,
                    saml_entity_id = :saml_entity_id,
                    saml_sso_url = :saml_sso_url,
                    saml_certificates = CAST(:saml_certificates AS jsonb),
                    saml_metadata_url = :saml_metadata_url,
                    saml_options = CAST(:saml_options AS jsonb)
                WHERE name = :name
                SQL,
            $parameters,
        );
    }

    #[\Override]
    public function delete(ConnectionName $name): void
    {
        $this->database->execute('DELETE FROM connections WHERE name = :name', ['name' => $name->value]);
    }

    /**
     * @return array<string, string|bool|null>
     */
    private static function parameters(Connection $connection): array
    {
        $oidc = $connection->oidc;
        $saml = $connection->saml;

        return [
            'name' => $connection->name->value,
            'display_name' => $connection->displayName,
            'strategy' => $connection->strategy->value,
            'is_enabled' => $connection->isEnabled,
            'is_domain_connection' => $connection->isDomainConnection,
            'oidc_issuer' => $oidc?->issuer->value,
            'oidc_client_id' => $oidc?->clientId,
            'oidc_client_secret_encrypted' => $oidc?->encryptedClientSecret,
            'oidc_scope' => $oidc?->scope->toString(),
            'oidc_authorization_endpoint' => $oidc?->authorizationEndpoint->value,
            'oidc_token_endpoint' => $oidc?->tokenEndpoint->value,
            'oidc_jwks_uri' => $oidc?->jwksUri->value,
            'created_at' => Timestamp::toDatabase($connection->createdAt),
            'allow_sign_up' => $connection->allowsSignUp,
            'require_verified_email' => $connection->requiresVerifiedEmail,
            'saml_entity_id' => $saml?->entityId,
            'saml_sso_url' => $saml?->singleSignOnUrl->value,
            'saml_certificates' => $saml === null ? null : Jsonb::encode(array_map(
                static fn (SamlCertificate $certificate): array => [
                    'pem' => $certificate->pem,
                    'not_after' => Timestamp::toDatabaseOrNull($certificate->notAfter),
                ],
                $saml->certificates,
            )),
            'saml_metadata_url' => $saml?->metadataUrl?->value,
            'saml_options' => $saml === null ? null : Jsonb::encode($saml->options->toArray()),
        ];
    }

    /**
     * @param ConnectionRow $row
     */
    private static function hydrate(array $row): Connection
    {
        $oidc = null;
        if (
            $row['oidc_issuer'] !== null
            && $row['oidc_client_id'] !== null
            && $row['oidc_client_secret_encrypted'] !== null
            && $row['oidc_scope'] !== null
            && $row['oidc_authorization_endpoint'] !== null
            && $row['oidc_token_endpoint'] !== null
            && $row['oidc_jwks_uri'] !== null
        ) {
            $oidc = OidcSettings::of(
                $row['oidc_issuer'],
                $row['oidc_client_id'],
                $row['oidc_client_secret_encrypted'],
                ScopeSet::fromString($row['oidc_scope']),
                $row['oidc_authorization_endpoint'],
                $row['oidc_token_endpoint'],
                $row['oidc_jwks_uri'],
            );
        }

        $saml = null;
        if (
            $row['saml_entity_id'] !== null
            && $row['saml_sso_url'] !== null
            && $row['saml_certificates'] !== null
            && $row['saml_options'] !== null
        ) {
            /** @var list<array{pem: string, not_after: string|null}> $certificates */
            $certificates = json_decode($row['saml_certificates'], true, 8, JSON_THROW_ON_ERROR);
            /** @var array<string, mixed> $options */
            $options = json_decode($row['saml_options'], true, 8, JSON_THROW_ON_ERROR);
            $saml = SamlSettings::of(
                $row['saml_entity_id'],
                Url::fromString($row['saml_sso_url']),
                array_map(
                    static fn (array $certificate): SamlCertificate => SamlCertificate::fromPem(
                        $certificate['pem'],
                        Timestamp::fromDatabaseOrNull($certificate['not_after']),
                    ),
                    $certificates,
                ),
                $row['saml_metadata_url'] === null ? null : Url::fromString($row['saml_metadata_url']),
                SamlOptions::fromArray($options),
            );
        }

        return Connection::reconstitute(
            ConnectionName::fromString($row['name']),
            $row['display_name'],
            ConnectionStrategy::from($row['strategy']),
            $row['is_enabled'],
            $row['is_domain_connection'],
            $oidc,
            Timestamp::fromDatabase($row['created_at']),
            $row['allow_sign_up'],
            $row['require_verified_email'],
            $saml,
        );
    }
}
