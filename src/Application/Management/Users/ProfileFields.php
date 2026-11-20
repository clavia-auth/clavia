<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Domain\Identity\Profile;

/**
 * Builds a {@see Profile} from the claim names the Management API uses.
 */
final class ProfileFields
{
    private function __construct()
    {
    }

    /**
     * @param array<'name'|'given_name'|'family_name'|'nickname'|'picture'|'locale', string|null> $changes
     *
     * @throws \Clavia\Domain\Shared\InvalidValue
     */
    public static function apply(Profile $profile, array $changes): Profile
    {
        $field = static fn (string $claim, ?string $current): ?string
            => array_key_exists($claim, $changes) ? $changes[$claim] : $current;

        return Profile::of(
            $field('name', $profile->name),
            $field('given_name', $profile->givenName),
            $field('family_name', $profile->familyName),
            $field('nickname', $profile->nickname),
            $field('picture', $profile->picture?->value),
            $field('locale', $profile->locale),
        );
    }
}
