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
use Clavia\Application\Management\Roles\DescribedPermission;
use Clavia\Application\Management\Roles\DescribedRole;
use Clavia\Application\Management\Roles\EffectivePermission;
use Clavia\Application\Management\Users\DescribedConsent;
use Clavia\Application\Management\Users\ManagedUser;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
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
 * `EffectivePermission`, `UserConsent`, the `…Page` envelopes).
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
            'email' => $user->email,
            'email_verified' => $user->isEmailVerified(),
            'is_active' => $user->isActive(),
            'has_password' => $user->passwordHash() !== null,
            'mfa_enrolled' => $managed->mfaEnrolled,
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
    private static function instant(DateTimeImmutable $instant): string
    {
        return $instant->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
    }
}
