<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management;

/**
 * The permissions the Management API defines: a verb on a resource, in the convention
 * the hosted providers use (`read:users`, `delete:clients`).
 *
 * One list, used twice: it is what `clavia management-api:register` writes onto the
 * Management API's own registration, and it is what each operation of the API
 * requires — the OpenAPI document names them, and a test keeps the two identical. That
 * is what stops an operation from demanding a permission nobody can be granted.
 *
 * `read` covers listing and fetching one: they disclose the same facts.
 *
 * `create:user_tickets` is a ticket in Auth0's sense: a one-time link mailed to a person, here to
 * choose a password. It is its own permission because it reaches the person's mailbox, not
 * their record, and `update:users` never suffices.
 *
 * `create:signing_keys` rotates the signing key (a rotation makes a new one), as the hosted
 * providers name it; nothing in this API reads, exports or deletes key material.
 *
 * `read:relationships` reads an API's relationship graph and tries its decisions
 * (docs/design/fine-grained-authorization.md §5.6): the API's data about people, asked about anyone,
 * so not part of `read:resource_servers`, which is configuration.
 *
 * `update:roles` is the one to guard most carefully: it can attach any permission on any
 * API to a role and give that role to anyone, the caller included. Giving somebody a role
 * needs it wherever that happens — on the role or on the account — and `update:users`
 * never suffices.
 */
enum ManagementPermission: string
{
    case ReadUsers = 'read:users';
    case CreateUsers = 'create:users';
    case UpdateUsers = 'update:users';
    case DeleteUsers = 'delete:users';
    /**
     * Writing an account's application metadata, which claim mappings copy into tokens and APIs
     * authorize on: granting access, which `update:users` (a name, an address) does not imply.
     */
    case UpdateUsersAppMetadata = 'update:users_app_metadata';
    case ReadClients = 'read:clients';
    case CreateClients = 'create:clients';
    case UpdateClients = 'update:clients';
    case DeleteClients = 'delete:clients';
    case ReadResourceServers = 'read:resource_servers';
    case CreateResourceServers = 'create:resource_servers';
    case UpdateResourceServers = 'update:resource_servers';
    case DeleteResourceServers = 'delete:resource_servers';
    case ReadRelationships = 'read:relationships';
    case ReadRoles = 'read:roles';
    case CreateRoles = 'create:roles';
    case UpdateRoles = 'update:roles';
    case DeleteRoles = 'delete:roles';
    case ReadConnections = 'read:connections';
    case CreateConnections = 'create:connections';
    case UpdateConnections = 'update:connections';
    case DeleteConnections = 'delete:connections';
    case CreateUserTickets = 'create:user_tickets';
    case ReadAuditEvents = 'read:audit_events';
    case ReadSigningKeys = 'read:signing_keys';
    case CreateSigningKeys = 'create:signing_keys';
    case ReadInitialAccessTokens = 'read:initial_access_tokens';
    case CreateInitialAccessTokens = 'create:initial_access_tokens';
    case DeleteInitialAccessTokens = 'delete:initial_access_tokens';
    case ReadProvisioningTokens = 'read:provisioning_tokens';
    case CreateProvisioningTokens = 'create:provisioning_tokens';
    case DeleteProvisioningTokens = 'delete:provisioning_tokens';
    case ReadWebhooks = 'read:webhooks';
    case CreateWebhooks = 'create:webhooks';
    case UpdateWebhooks = 'update:webhooks';
    case DeleteWebhooks = 'delete:webhooks';

    /** A sentence for the permission, shown wherever one is assigned. */
    /**
     * Whether this permission is needed by a field of an operation rather than by the operation
     * (`app_metadata` on `PATCH /api/v1/users/{user_id}`): OpenAPI's security requirements cannot say
     * "only when this is sent", so its handler checks it, and the document says so in the
     * operation's description.
     */
    public function isRequiredByAField(): bool
    {
        return $this === self::UpdateUsersAppMetadata;
    }

    public function description(): string
    {
        [$verb, $resource] = explode(':', $this->value, 2) + [1 => ''];

        return match ($verb) {
            'read' => 'View',
            'create' => 'Create',
            'update' => 'Modify',
            default => 'Delete',
        } . ' ' . match ($resource) {
            'users' => 'end users',
            'users_app_metadata' => 'the application metadata of end users',
            'clients' => 'client applications',
            'roles' => 'roles and who holds them',
            'connections' => 'the ways users sign in',
            'user_tickets' => 'links for end users to choose a password',
            'audit_events' => 'the audit trail',
            'signing_keys' => 'the keys tokens are signed with',
            'webhooks' => 'the endpoints audit events are sent to',
            'provisioning_tokens' => 'the tokens directories provision accounts with',
            'relationships' => 'the relationships of APIs, and what they decide',
            default => 'APIs',
        };
    }
}
