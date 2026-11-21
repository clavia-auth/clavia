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
    case ReadClients = 'read:clients';
    case CreateClients = 'create:clients';
    case UpdateClients = 'update:clients';
    case DeleteClients = 'delete:clients';
    case ReadResourceServers = 'read:resource_servers';
    case CreateResourceServers = 'create:resource_servers';
    case UpdateResourceServers = 'update:resource_servers';
    case DeleteResourceServers = 'delete:resource_servers';
    case ReadRoles = 'read:roles';
    case CreateRoles = 'create:roles';
    case UpdateRoles = 'update:roles';
    case DeleteRoles = 'delete:roles';
    case ReadConnections = 'read:connections';
    case CreateConnections = 'create:connections';
    case UpdateConnections = 'update:connections';
    case DeleteConnections = 'delete:connections';

    /** A sentence for the permission, shown wherever one is assigned. */
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
            'clients' => 'client applications',
            'roles' => 'roles and who holds them',
            'connections' => 'the ways users sign in',
            default => 'APIs',
        };
    }
}
