<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users\Export;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserRepository;
use DateTimeImmutable;
use DateTimeZone;

/**
 * Writes the accounts of a connection out as NDJSON, one JSON object per line, in the shape an import
 * line takes, so an export of one pool imports into another (or into another server) as it is:
 *
 * - `email`, `email_verified`, `is_active`, and the profile fields that are set (`name`, `given_name`,
 *   `family_name`, `nickname`, `picture`, `locale`);
 * - `user_id`, `connection`, `created_at` and `updated_at`, which say where the account came from,
 *   and which an import ignores.
 *
 * **Never a password hash**, nor anything of a second factor, a passkey, a linked identity or a
 * session: an export is a copy of the directory, not of anybody's means of signing in. An account
 * moved by an export chooses its password again (a reset link) where it lands.
 *
 * The accounts are read a page at a time by id ({@see UserRepository::inConnection()}): one made or
 * deleted meanwhile is in it or not, and no account is written twice.
 */
final readonly class ExportUsers
{
    private const int PAGE = 500;

    private const int JSON = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

    public function __construct(private UserRepository $users)
    {
    }

    public function __invoke(ConnectionName $connection): ExportedUsers
    {
        $content = '';
        $count = 0;
        $after = null;
        do {
            $page = $this->users->inConnection($connection, $after, self::PAGE);
            foreach ($page as $user) {
                $content .= json_encode(self::line($user), self::JSON) . "\n";
                ++$count;
                $after = $user->id;
            }
        } while (count($page) === self::PAGE);

        return new ExportedUsers($content, $count);
    }

    /** @return array<string, string|bool> */
    public static function line(User $user): array
    {
        $profile = $user->profile();
        $line = [
            'user_id' => $user->id->value,
            'connection' => $user->connection->value,
            'email' => $user->email,
            'email_verified' => $user->isEmailVerified(),
            'is_active' => $user->isActive(),
        ];
        // Left out when unset: an import takes a profile field as a string, never null.
        foreach (
            [
                'name' => $profile->name,
                'given_name' => $profile->givenName,
                'family_name' => $profile->familyName,
                'nickname' => $profile->nickname,
                'picture' => $profile->picture?->value,
                'locale' => $profile->locale,
            ] as $field => $value
        ) {
            if ($value !== null) {
                $line[$field] = $value;
            }
        }

        return $line + [
            'created_at' => self::instant($user->createdAt),
            'updated_at' => self::instant($user->updatedAt()),
        ];
    }

    private static function instant(DateTimeImmutable $instant): string
    {
        return $instant->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
    }
}
