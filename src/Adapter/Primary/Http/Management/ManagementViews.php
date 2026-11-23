<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Clients\ClientWithSecret;
use Clavia\Application\Management\Connections\DescribedConnection;
use Clavia\Application\Management\Roles\DescribedPermission;
use Clavia\Application\Management\Roles\DescribedRole;
use Clavia\Application\Management\Roles\EffectivePermission;
use Clavia\Application\Management\Users\DescribedConsent;
use Clavia\Application\Management\Users\ManagedSession;
use Clavia\Application\Management\Users\ManagedUser;
use Clavia\Application\Oidc\Keys\ListedSigningKey;
use Clavia\Application\Oidc\Keys\Rotation;
use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\Url;
use DateTimeImmutable;
use DateTimeZone;

/**
 * The JSON shape of each resource, as `docs/openapi/management-api.yaml` describes it
 * (`User`, `Client`, `ClientWithSecret`, `ResourceServer`, `Role`, `RoleWithPermissions`,
 * `EffectivePermission`, `UserConsent`, `Connection`, `Identity`, the `…Page` envelopes).
 *
 * What is left out is left out on purpose: a password hash or a client secret hash is
 * never part of a resource, and a client secret appears only in {@see self::clientWithSecret()}.
 */
final class ManagementViews
{
    private function __construct()
    {
    }

    /**
     * @template T
     *
     * @param Page<T>                          $page
     * @param callable(T): array<string, mixed> $item
     *
     * @return array{items: list<array<string, mixed>>, total: int, page: int, per_page: int}
     */
    public static function page(Page $page, callable $item): array
    {
        return [
            'items' => array_map($item, $page->items),
            'total' => $page->total,
            'page' => $page->request->page,
            'per_page' => $page->request->perPage,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function user(ManagedUser $managed): array
    {
        $user = $managed->user;
        $profile = $user->profile();

        return [
            'id' => $user->id->value,
            'connection' => $user->connection->value,
            'email' => $user->email,
            'email_verified' => $user->isEmailVerified(),
            'is_active' => $user->isActive(),
            'has_password' => $user->passwordHash() !== null,
            'mfa_enrolled' => $managed->mfaEnrolled,
            'passkey_count' => $managed->passkeyCount,
            'name' => $profile->name,
            'given_name' => $profile->givenName,
            'family_name' => $profile->familyName,
            'nickname' => $profile->nickname,
            'picture' => $profile->picture?->value,
            'locale' => $profile->locale,
            'created_at' => self::instant($user->createdAt),
            'updated_at' => self::instant($user->updatedAt()),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function client(Client $client): array
    {
        return [
            'client_id' => $client->id->value,
            'name' => $client->name,
            'client_type' => $client->type->value,
            'token_endpoint_auth_method' => $client->authMethod->value,
            'redirect_uris' => array_map(static fn (Url $uri): string => $uri->value, $client->redirectUris),
            'grant_types' => array_map(static fn (GrantType $type): string => $type->value, $client->grantTypes),
            'response_types' => array_map(
                static fn (ResponseType $type): string => $type->value,
                $client->responseTypes,
            ),
            'post_logout_redirect_uris' => array_map(
                static fn (Url $uri): string => $uri->value,
                $client->postLogoutRedirectUris,
            ),
            'is_first_party' => $client->isFirstParty(),
            'connections' => array_map(
                static fn (ConnectionName $connection): string => $connection->value,
                $client->connections,
            ),
            'backchannel_logout_uri' => $client->backChannelLogout?->uri->value,
            'backchannel_logout_session_required' => $client->backChannelLogout->sessionRequired ?? false,
            'require_pkce' => $client->requiresPkce,
            'mfa_policy' => $client->mfaPolicy->value,
            'require_pushed_authorization_requests' => $client->requiresPushedAuthorizationRequests,
            'dpop_bound_access_tokens' => $client->requiresDpop,
            'created_at' => self::instant($client->createdAt),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function clientWithSecret(ClientWithSecret $registered): array
    {
        return self::client($registered->client) + ['client_secret' => $registered->secret];
    }

    /**
     * @return array<string, mixed>
     */
    public static function resourceServer(ResourceServer $api): array
    {
        return [
            'id' => $api->id->value,
            'identifier' => $api->identifier->value,
            'name' => $api->name,
            'permissions' => array_map(
                static fn (Permission $permission): array => [
                    'value' => $permission->value->value,
                    'description' => $permission->description,
                ],
                $api->permissions,
            ),
            'is_system' => $api->isSystem,
            'enforce_policies' => $api->enforcePolicies,
            'allow_skipping_consent' => $api->allowSkippingConsent,
            'access_token_format' => $api->accessTokenFormat->value,
            'mfa_policy' => $api->mfaPolicy->value,
            'created_at' => self::instant($api->createdAt),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function role(Role $role): array
    {
        return [
            'id' => $role->id->value,
            'name' => $role->name,
            'description' => $role->description,
            'created_at' => self::instant($role->createdAt),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function roleWithPermissions(DescribedRole $described): array
    {
        return self::role($described->role) + [
            'permissions' => array_map(self::rolePermission(...), $described->permissions),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function effectivePermission(EffectivePermission $effective): array
    {
        return self::rolePermission($effective->permission) + [
            'roles' => array_map(
                static fn (Role $role): array => ['id' => $role->id->value, 'name' => $role->name],
                $effective->roles,
            ),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function consent(DescribedConsent $described): array
    {
        $scopes = $described->consent->scope->toList();
        sort($scopes);

        return [
            'client_id' => $described->client->id->value,
            'client_name' => $described->client->name,
            'is_first_party' => $described->client->isFirstParty(),
            'audience' => $described->audience?->value,
            'scopes' => $scopes,
            'granted_at' => self::instant($described->consent->grantedAt),
            'updated_at' => self::instant($described->consent->updatedAt),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function session(ManagedSession $managed): array
    {
        $session = $managed->session;

        return [
            'sid' => $session->sid,
            'created_at' => self::instant($session->authenticatedAt),
            'expires_at' => self::instant($session->expiresAt),
            'amr' => array_map(static fn (AuthenticationMethod $method): string => $method->value, $session->methods),
            'connection' => $session->connection->value,
            'clients' => array_map(
                static fn (Client $client): array => ['client_id' => $client->id->value, 'name' => $client->name],
                $managed->clients,
            ),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function connection(DescribedConnection $described): array
    {
        $connection = $described->connection;

        return [
            'name' => $connection->name->value,
            'display_name' => $connection->displayName,
            'strategy' => $connection->strategy->value,
            'is_enabled' => $connection->isEnabled,
            'is_domain_connection' => $connection->isDomainConnection,
            'allow_sign_up' => $connection->allowsSignUp,
            'require_verified_email' => $connection->requiresVerifiedEmail,
            'configured' => $described->configured,
            'usable' => $described->usable,
            // The secret is never part of it: stored encrypted, sent only to the provider.
            'oidc_issuer' => $connection->oidc?->issuer->value,
            'oidc_client_id' => $connection->oidc?->clientId,
            'oidc_scope' => $connection->oidc?->scope->toString(),
            'created_at' => self::instant($connection->createdAt),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function identity(ExternalIdentity $identity): array
    {
        return [
            'connection' => $identity->provider->value,
            'subject' => $identity->subject,
            'email' => $identity->email,
            'linked_at' => self::instant($identity->linkedAt),
        ];
    }

    /**
     * A passkey as an operator sees it: what it is called, synced or device-bound, its maker, and
     * when it was added and used. Never its credential id or its key.
     *
     * @return array<string, mixed>
     */
    public static function passkey(Passkey $passkey): array
    {
        return [
            'id' => $passkey->id->value,
            'name' => $passkey->name->value,
            'synced' => $passkey->isSynced(),
            'backed_up' => $passkey->backedUp,
            'aaguid' => $passkey->aaguid?->value,
            'created_at' => self::instant($passkey->createdAt),
            'last_used_at' => $passkey->lastUsedAt === null ? null : self::instant($passkey->lastUsedAt),
        ];
    }

    /**
     * A signing key as an operator sees it: its `kid`, algorithm and place in the rotation — never
     * its material. The public key is the JWKS's to publish; the private one never leaves the
     * signing backend.
     *
     * @return array<string, mixed>
     */
    public static function signingKey(ListedSigningKey $listed): array
    {
        $key = $listed->key;
        $retiredAt = $key->retiredAt();
        $until = $key->publishedUntil();

        return [
            'kid' => $key->kid(),
            'algorithm' => $key->algorithm()->value,
            'status' => $key->status()->value,
            'published' => $listed->published,
            'created_at' => self::instant($key->createdAt),
            'retired_at' => $retiredAt === null ? null : self::instant($retiredAt),
            'published_until' => $until === null ? null : self::instant($until),
        ];
    }

    /**
     * What a rotation did: the key that signs now, and the one it replaced, which stays published
     * for the grace period.
     *
     * @return array<string, mixed>
     */
    public static function rotation(Rotation $rotation): array
    {
        return [
            'active' => self::signingKey(new ListedSigningKey($rotation->active, true)),
            'retired' => $rotation->retired === null
                ? null
                : self::signingKey(new ListedSigningKey($rotation->retired, true)),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function rolePermission(DescribedPermission $permission): array
    {
        return [
            'resource_server_id' => $permission->resourceServerId->value,
            'resource_server_identifier' => $permission->resourceServerIdentifier->value,
            'value' => $permission->value,
            'description' => $permission->description,
        ];
    }

    /** RFC 3339, in UTC, to the second. */
    /**
     * @return array<string, mixed>
     */
    public static function auditEvent(AuditEvent $event): array
    {
        return [
            'id' => $event->id->value,
            'type' => $event->type->value,
            'occurred_at' => self::instant($event->occurredAt),
            'outcome' => $event->outcome->value,
            'actor' => [
                'kind' => $event->actor->kind->value,
                'user_id' => $event->actor->userId?->value,
                'client_id' => $event->actor->clientId?->value,
            ],
            'target' => $event->target === null
                ? null
                : ['type' => $event->target->type->value, 'id' => $event->target->id],
            'details' => (object) $event->details,
            'client_address' => $event->clientAddress,
            'user_agent' => $event->userAgent,
        ];
    }

    private static function instant(DateTimeImmutable $instant): string
    {
        return $instant->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
    }
}
