<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Provisioning\ScimGroup;
use Clavia\Domain\Provisioning\ScimGroupResource;
use DateTimeImmutable;
use DateTimeZone;

/**
 * A directory's group as a SCIM `Group` resource (RFC 7643 §4.2, §3.1 `meta`): its name,
 * `externalId`, and members as references to their `User` resources. Members are left out when the
 * request asks (`excludedAttributes=members`, RFC 7644 §3.4.2.5), as directories do before they
 * change a large group.
 */
final class ScimGroupDocument
{
    private function __construct()
    {
    }

    /**
     * @param non-empty-string $baseUrl
     *
     * @return array<string, mixed>
     */
    public static function of(ScimGroup $group, string $baseUrl, bool $withMembers = true): array
    {
        return array_filter([
            'schemas' => [ScimGroupResource::SCHEMA],
            'id' => $group->id->value,
            'externalId' => $group->externalId,
            'displayName' => $group->displayName,
            'members' => $withMembers ? array_map(
                static fn (UserId $member): array => [
                    'value' => $member->value,
                    '$ref' => ScimUserDocument::location($member->value, $baseUrl),
                    'type' => 'User',
                ],
                $group->members,
            ) : null,
            'meta' => [
                'resourceType' => 'Group',
                'created' => self::instant($group->createdAt),
                'lastModified' => self::instant($group->updatedAt),
                'location' => self::location($group->id->value, $baseUrl),
                'version' => self::etag($group),
            ],
        ], static fn (mixed $value): bool => $value !== null);
    }

    public static function etag(ScimGroup $group): string
    {
        return 'W/"' . $group->version() . '"';
    }

    /** @param non-empty-string $baseUrl */
    public static function location(string $id, string $baseUrl): string
    {
        return $baseUrl . '/Groups/' . $id;
    }

    private static function instant(DateTimeImmutable $instant): string
    {
        return $instant->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
    }
}
