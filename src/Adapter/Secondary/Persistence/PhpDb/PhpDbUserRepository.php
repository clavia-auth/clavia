<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\Profile;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use Throwable;

/**
 * Users in the `users` table, each in its `connection`; an address is unique within one.
 */
final readonly class PhpDbUserRepository implements UserRepository
{
    private const string COLUMNS = 'id, connection, email, password_hash, email_verified, is_active, name, '
        . 'given_name, family_name, nickname, picture, locale, created_at, updated_at';

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function find(UserId $id): ?User
    {
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM users WHERE id = :id',
            ['id' => $id->value],
        );

        return $row === null ? null : $this->hydrate($row);
    }

    #[\Override]
    public function findByEmail(ConnectionName $connection, string $email): ?User
    {
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM users WHERE connection = :connection AND email = :email',
            ['connection' => $connection->value, 'email' => $email],
        );

        return $row === null ? null : $this->hydrate($row);
    }

    #[\Override]
    public function matchingEmail(string $email, array $connections): array
    {
        if ($connections === []) {
            return [];
        }
        $parameters = ['email' => $email];
        $placeholders = [];
        foreach ($connections as $index => $connection) {
            $placeholders[] = ':connection_' . $index;
            $parameters['connection_' . $index] = $connection->value;
        }

        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM users WHERE lower(email) = lower(:email)'
            . ' AND connection IN (' . implode(', ', $placeholders) . ') ORDER BY created_at, id',
            $parameters,
        );

        return array_map($this->hydrate(...), $rows);
    }

    #[\Override]
    public function countIn(ConnectionName $connection): int
    {
        /** @var int|string $count */
        $count = $this->database->fetchValue(
            'SELECT count(*) FROM users WHERE connection = :connection',
            ['connection' => $connection->value],
        );

        return (int) $count;
    }

    #[\Override]
    public function inConnection(ConnectionName $connection, ?UserId $after, int $limit): array
    {
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM users WHERE connection = :connection'
            . ($after === null ? '' : ' AND id > :after') . ' ORDER BY id LIMIT :limit',
            ['connection' => $connection->value, 'limit' => $limit]
                + ($after === null ? [] : ['after' => $after->value]),
        );

        return array_map($this->hydrate(...), $rows);
    }

    #[\Override]
    public function save(User $user): void
    {
        try {
            $this->write($user);
        } catch (Throwable $failure) {
            throw Constraint::isUniqueViolation($failure, 'uq_users_connection_email')
                ? new AlreadyExists(
                    sprintf("Another account in '%s' uses the address %s.", $user->connection->value, $user->email),
                    0,
                    $failure,
                )
                : $failure;
        }
    }

    #[\Override]
    public function delete(UserId $id): void
    {
        $this->database->execute('DELETE FROM users WHERE id = :id', ['id' => $id->value]);
    }

    #[\Override]
    public function page(PageRequest $request): Page
    {
        $search = Search::across($request, ['email']);
        /** @var int|string $total */
        $total = $this->database->fetchValue('SELECT count(*) FROM users ' . $search->where, $search->parameters);
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM users ' . $search->where
            . ' ORDER BY created_at DESC, id LIMIT :limit OFFSET :offset',
            $search->pageParameters($request),
        );

        return new Page(array_map($this->hydrate(...), $rows), max(0, (int) $total), $request);
    }

    private function write(User $user): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO users (
                    id, connection, email, password_hash, email_verified, is_active, name, given_name,
                    family_name, nickname, picture, locale, created_at, updated_at
                ) VALUES (
                    :id, :connection, :email, :password_hash, :email_verified, :is_active, :name, :given_name,
                    :family_name, :nickname, :picture, :locale, :created_at, :updated_at
                )
                ON CONFLICT (id) DO UPDATE SET
                    email = EXCLUDED.email,
                    password_hash = EXCLUDED.password_hash,
                    email_verified = EXCLUDED.email_verified,
                    is_active = EXCLUDED.is_active,
                    name = EXCLUDED.name,
                    given_name = EXCLUDED.given_name,
                    family_name = EXCLUDED.family_name,
                    nickname = EXCLUDED.nickname,
                    picture = EXCLUDED.picture,
                    locale = EXCLUDED.locale,
                    updated_at = EXCLUDED.updated_at
                SQL,
            [
                'id' => $user->id->value,
                'connection' => $user->connection->value,
                'email' => $user->email,
                'password_hash' => $user->passwordHash(),
                'email_verified' => $user->isEmailVerified(),
                'is_active' => $user->isActive(),
                'name' => $user->profile()->name,
                'given_name' => $user->profile()->givenName,
                'family_name' => $user->profile()->familyName,
                'nickname' => $user->profile()->nickname,
                'picture' => $user->profile()->picture?->value,
                'locale' => $user->profile()->locale,
                'created_at' => Timestamp::toDatabase($user->createdAt),
                'updated_at' => Timestamp::toDatabase($user->updatedAt()),
            ],
        );
    }

    /**
     * @param array<string, mixed> $row
     */
    private function hydrate(array $row): User
    {
        /**
         * @var array{id: string, connection: string, email: string, password_hash: string|null,
         *            email_verified: bool,
         *            is_active: bool, name: string|null, given_name: string|null, family_name: string|null,
         *            nickname: string|null, picture: string|null, locale: string|null, created_at: string,
         *            updated_at: string} $row
         */
        return User::reconstitute(
            UserId::fromString($row['id']),
            $row['email'],
            $row['password_hash'],
            $row['email_verified'],
            $row['is_active'],
            Profile::of(
                $row['name'],
                $row['given_name'],
                $row['family_name'],
                $row['nickname'],
                $row['picture'],
                $row['locale'],
            ),
            Timestamp::fromDatabase($row['created_at']),
            Timestamp::fromDatabase($row['updated_at']),
            ConnectionName::fromString($row['connection']),
        );
    }
}
