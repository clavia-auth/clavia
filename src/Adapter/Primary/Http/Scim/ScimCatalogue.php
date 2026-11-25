<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Clavia\Domain\Provisioning\ScimGroupResource;
use Clavia\Domain\Provisioning\ScimUser;

/**
 * What `/ResourceTypes` and `/Schemas` list (RFC 7643 §6, §7): the resource types served and the
 * attributes this server keeps of each. Others are accepted and ignored, so a directory's
 * administrator can see here which of theirs reach an account (docs/design/scim-provisioning.md §2).
 */
final class ScimCatalogue
{
    private const string RESOURCE_TYPE_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ResourceType';
    private const string SCHEMA_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Schema';

    private function __construct()
    {
    }

    /**
     * @param non-empty-string $baseUrl
     *
     * @return array{ResourceTypes: list<array<string, mixed>>, Schemas: list<array<string, mixed>>}
     */
    public static function of(string $baseUrl): array
    {
        return [
            'ResourceTypes' => [[
                'schemas' => [self::RESOURCE_TYPE_SCHEMA],
                'id' => 'User',
                'name' => 'User',
                'endpoint' => '/Users',
                'description' => 'An account of the connection the provisioning token reaches.',
                'schema' => ScimUser::SCHEMA,
                'meta' => ['resourceType' => 'ResourceType', 'location' => $baseUrl . '/ResourceTypes/User'],
            ], [
                'schemas' => [self::RESOURCE_TYPE_SCHEMA],
                'id' => 'Group',
                'name' => 'Group',
                'endpoint' => '/Groups',
                'description' => "A group of the connection's accounts; one named as a provisionable role grants it.",
                'schema' => ScimGroupResource::SCHEMA,
                'meta' => ['resourceType' => 'ResourceType', 'location' => $baseUrl . '/ResourceTypes/Group'],
            ]],
            'Schemas' => [[
                'schemas' => [self::SCHEMA_SCHEMA],
                'id' => ScimUser::SCHEMA,
                'name' => 'User',
                'description' => 'The attributes of an account this server keeps; any other is ignored.',
                'attributes' => [
                    self::attribute(
                        'userName',
                        'Unique in the connection, ignoring case.',
                        required: true,
                        uniqueness: 'server',
                    ),
                    self::attribute('externalId', "The directory's own identifier for the person.", caseExact: true),
                    self::attribute('active', 'Whether the account may sign in.', type: 'boolean'),
                    self::attribute('displayName', 'The name shown for the person.'),
                    self::attribute('name', 'The components of the name.', type: 'complex', subAttributes: [
                        self::attribute('givenName', 'The given name.'),
                        self::attribute('familyName', 'The family name.'),
                        self::attribute(
                            'formatted',
                            'The whole name, when there is no displayName.',
                            returned: 'never',
                        ),
                    ]),
                    self::attribute('nickName', 'A casual name.'),
                    self::attribute('locale', 'A language tag, such as en-US.'),
                    self::attribute(
                        'emails',
                        "The account's address is the primary one, or the first.",
                        type: 'complex',
                        multiValued: true,
                        subAttributes: [
                            self::attribute('value', 'An email address.'),
                            self::attribute('primary', 'Whether it is the address.', type: 'boolean'),
                        ],
                    ),
                ],
                'meta' => ['resourceType' => 'Schema', 'location' => $baseUrl . '/Schemas/' . ScimUser::SCHEMA],
            ], [
                'schemas' => [self::SCHEMA_SCHEMA],
                'id' => ScimGroupResource::SCHEMA,
                'name' => 'Group',
                'description' => 'A group of accounts. One named exactly as a provisionable role gives its members '
                    . 'that role.',
                'attributes' => [
                    self::attribute('displayName', 'Unique in the connection, ignoring case.', required: true),
                    self::attribute('externalId', "The directory's own identifier for the group.", caseExact: true),
                    self::attribute(
                        'members',
                        'The accounts of the group.',
                        type: 'complex',
                        multiValued: true,
                        subAttributes: [
                            self::attribute('value', 'The id of a User of the connection.', caseExact: true),
                        ],
                    ),
                ],
                'meta' => [
                    'resourceType' => 'Schema',
                    'location' => $baseUrl . '/Schemas/' . ScimGroupResource::SCHEMA,
                ],
            ]],
        ];
    }

    /**
     * An attribute definition (RFC 7643 §7), `readWrite` and returned by default.
     *
     * @param list<array<string, mixed>> $subAttributes
     *
     * @return array<string, mixed>
     */
    private static function attribute(
        string $name,
        string $description,
        string $type = 'string',
        bool $multiValued = false,
        bool $required = false,
        bool $caseExact = false,
        string $uniqueness = 'none',
        string $returned = 'default',
        array $subAttributes = [],
    ): array {
        $attribute = [
            'name' => $name,
            'type' => $type,
            'multiValued' => $multiValued,
            'description' => $description,
            'required' => $required,
            'mutability' => 'readWrite',
            'returned' => $returned,
        ];
        if ($type === 'string') {
            $attribute += ['caseExact' => $caseExact, 'uniqueness' => $uniqueness];
        }

        return $subAttributes === [] ? $attribute : $attribute + ['subAttributes' => $subAttributes];
    }
}
