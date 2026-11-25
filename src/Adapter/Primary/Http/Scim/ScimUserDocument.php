<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Clavia\Application\Provisioning\Users\ProvisionedUser;
use Clavia\Domain\Provisioning\ScimUser;
use DateTimeImmutable;
use DateTimeZone;

/**
 * A provisioned account as a SCIM `User` resource (RFC 7643 §4.1, §3.1 `meta`): what was kept of what
 * the directory sent. An attribute with no value is left out (§2.5: unassigned, null and empty are
 * one).
 */
final class ScimUserDocument
{
    private function __construct()
    {
    }

    /**
     * @param non-empty-string $baseUrl
     *
     * @return array<string, mixed>
     */
    public static function of(ProvisionedUser $provisioned, string $baseUrl): array
    {
        $user = $provisioned->user;
        $account = $provisioned->account;
        $profile = $user->profile();
        $name = array_filter([
            'givenName' => $profile->givenName,
            'familyName' => $profile->familyName,
        ], static fn (?string $value): bool => $value !== null);

        return array_filter([
            'schemas' => [ScimUser::SCHEMA],
            'id' => $user->id->value,
            'externalId' => $account->externalId,
            'userName' => $account->userName,
            'active' => $user->isActive(),
            'displayName' => $profile->name,
            'name' => $name === [] ? null : $name,
            'nickName' => $profile->nickname,
            'locale' => $profile->locale,
            'emails' => [['value' => $user->email, 'primary' => true]],
            'meta' => [
                'resourceType' => 'User',
                'created' => self::instant($account->createdAt),
                'lastModified' => self::instant(max($account->updatedAt, $user->updatedAt())),
                'location' => self::location($user->id->value, $baseUrl),
            ],
        ], static fn (mixed $value): bool => $value !== null);
    }

    /** @param non-empty-string $baseUrl */
    public static function location(string $id, string $baseUrl): string
    {
        return $baseUrl . '/Users/' . $id;
    }

    private static function instant(DateTimeImmutable $instant): string
    {
        return $instant->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
    }
}
