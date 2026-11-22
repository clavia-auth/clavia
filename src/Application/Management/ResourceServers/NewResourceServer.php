<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

use Clavia\Domain\ResourceServer\AccessTokenFormat;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;

/**
 * An API to register.
 */
final readonly class NewResourceServer
{
    /**
     * @param string                     $identifier An absolute URI without a fragment, on a domain the operator
     *                                               owns, so that it cannot collide across deployments. Never
     *                                               dereferenced (RFC 8707 §2).
     * @param list<PermissionDefinition> $permissions
     * @param bool                       $enforcePolicies Whether a person's token carries only what their
     *                                                    roles grant on the API.
     * @param bool                       $allowSkippingConsent Whether first-party applications may do without
     *                                                         the consent screen for its permissions.
     * @param string                     $accessTokenFormat `opaque` or `jwt`: see {@see AccessTokenFormat}.
     */
    public function __construct(
        public string $identifier,
        public string $name = '',
        public array $permissions = [],
        public bool $enforcePolicies = false,
        public bool $allowSkippingConsent = true,
        public string $accessTokenFormat = 'opaque',
    ) {
    }

    /**
     * @param list<PermissionDefinition> $definitions
     *
     * @return list<Permission>
     *
     * @throws InvalidValue
     */
    public static function permissions(array $definitions): array
    {
        return array_map(
            static fn (PermissionDefinition $definition): Permission => Permission::of(
                $definition->value,
                $definition->description,
            ),
            $definitions,
        );
    }

    /**
     * @throws InvalidValue When the value names no format.
     */
    public static function accessTokenFormat(string $value): AccessTokenFormat
    {
        return AccessTokenFormat::tryFrom($value)
            ?? throw new InvalidValue("An access token format is 'opaque' or 'jwt'.");
    }

    /**
     * @throws InvalidValue When the identifier is not an absolute URI, or has a fragment.
     */
    public static function checkIdentifier(string $identifier): void
    {
        if (Url::fromString($identifier)->hasFragment()) {
            throw new InvalidValue('An API identifier must not contain a fragment.');
        }
    }
}
