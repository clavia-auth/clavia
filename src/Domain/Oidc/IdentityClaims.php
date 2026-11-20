<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Oidc;

use Clavia\Domain\Identity\User;
use Clavia\Domain\Shared\ScopeSet;

/**
 * The claims about a person that a grant of scope releases (OIDC Core §5.4): one
 * definition shared by the ID token and the userinfo endpoint, so the two cannot drift
 * on what a scope means.
 *
 * `sub` is always present. `profile` releases the profile claims that are set, plus
 * `updated_at`; `email` releases `email` and `email_verified`. Holding a token is not by
 * itself authority to read an address.
 */
final class IdentityClaims
{
    private function __construct()
    {
    }

    /**
     * @return array<non-empty-string, string|bool|int>
     */
    public static function of(User $user, ScopeSet $scope): array
    {
        $claims = ['sub' => $user->id->value];

        if ($scope->contains(OidcScope::PROFILE)) {
            $profile = $user->profile();
            // OIDC Core §5.1: an unknown value is left out, never sent as null or "".
            $claims += array_filter(
                [
                    'name' => $profile->name,
                    'given_name' => $profile->givenName,
                    'family_name' => $profile->familyName,
                    'nickname' => $profile->nickname,
                    'picture' => $profile->picture?->value,
                    'locale' => $profile->locale,
                ],
                static fn (?string $value): bool => $value !== null,
            );
            // Seconds since the epoch (OIDC Core §5.1), so a relying party knows its copy is stale.
            $claims['updated_at'] = $user->updatedAt()->getTimestamp();
        }

        if ($scope->contains(OidcScope::EMAIL)) {
            $claims['email'] = $user->email;
            $claims['email_verified'] = $user->isEmailVerified();
        }

        return $claims;
    }
}
