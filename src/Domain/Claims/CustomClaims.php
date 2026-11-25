<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Claims;

use LogicException;
use stdClass;

/**
 * Works the custom claims of one token out from its mappings: what each source reads of the
 * subject, a claim left out when its source has no value (never sent as null), constants only for
 * a token with no subject. Pure: the caller hands it the account and its roles.
 */
final readonly class CustomClaims
{
    public const int MAX_BYTES = 32_768;

    private function __construct()
    {
    }

    /**
     * @return array<non-empty-string, mixed>
     *
     * @throws CustomClaimsTooLarge
     * @throws LogicException When a stored mapping names a reserved claim.
     */
    public static function of(ClaimMappings $mappings, ?ClaimSubject $subject, ClaimDestination $destination): array
    {
        $claims = [];
        foreach ($mappings->mappings as $mapping) {
            if (! $mapping->goesTo($destination)) {
                continue;
            }
            $name = $mapping->name;
            if ($name->isReserved() && $name->value !== ClaimName::ROLES) {
                // Saved before the name joined the list: never let it reach a token.
                throw new LogicException('A stored custom claim mapping names a reserved claim.');
            }
            $value = self::read($mapping->source, $subject);
            if ($value !== null) {
                /** @psalm-suppress MixedAssignment The value is any JSON. */
                $claims[$name->value] = $value[0];
            }
        }
        $encoded = $claims === []
            ? ''
            : json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        if (strlen($encoded) > self::MAX_BYTES) {
            throw new CustomClaimsTooLarge(sprintf('The custom claims of one token pass %d bytes.', self::MAX_BYTES));
        }

        return $claims;
    }

    /** @return list{mixed}|null The value, boxed, or null when there is none. */
    private static function read(ClaimSource $source, ?ClaimSubject $subject): ?array
    {
        if ($source->kind === ClaimSourceKind::Constant) {
            return [json_decode((string) $source->constant, false, 16, JSON_THROW_ON_ERROR)];
        }
        if ($subject === null) {
            return null;
        }
        $user = $subject->user;
        $profile = $user->profile();

        /** @var mixed $value */
        $value = match ($source->kind) {
            ClaimSourceKind::Email => $user->email,
            ClaimSourceKind::EmailVerified => $user->isEmailVerified(),
            ClaimSourceKind::Connection => $user->connection->value,
            ClaimSourceKind::ProfileField => match ($source->path[0]) {
                'name' => $profile->name,
                'given_name' => $profile->givenName,
                'family_name' => $profile->familyName,
                'nickname' => $profile->nickname,
                'picture' => $profile->picture?->value,
                default => $profile->locale,
            },
            ClaimSourceKind::AppMetadata => $user->appMetadata()->at($source->path)[0] ?? null,
            ClaimSourceKind::Roles => $subject->roles === [] ? null : $subject->roles,
        };

        return $value === null ? null : [$value];
    }
}
