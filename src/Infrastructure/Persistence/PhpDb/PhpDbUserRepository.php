<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Infrastructure\Persistence\PhpDb;

use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;

/**
 * Users in the `users` table.
 */
final readonly class PhpDbUserRepository implements UserRepository
{
    private const string COLUMNS = 'id, email, password_hash, email_verified, is_active, created_at, updated_at';

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
    public function findByEmail(string $email): ?User
    {
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM users WHERE email = :email',
            ['email' => $email],
        );

        return $row === null ? null : $this->hydrate($row);
    }

    #[\Override]
    public function save(User $user): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO users (id, email, password_hash, email_verified, is_active, created_at, updated_at)
                VALUES (:id, :email, :password_hash, :email_verified, :is_active, :created_at, :updated_at)
                ON CONFLICT (id) DO UPDATE SET
                    password_hash = EXCLUDED.password_hash,
                    email_verified = EXCLUDED.email_verified,
                    is_active = EXCLUDED.is_active,
                    updated_at = EXCLUDED.updated_at
                SQL,
            [
                'id' => $user->id->value,
                'email' => $user->email,
                'password_hash' => $user->passwordHash(),
                'email_verified' => $user->isEmailVerified(),
                'is_active' => $user->isActive(),
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
         * @var array{id: string, email: string, password_hash: string|null, email_verified: bool,
         *            is_active: bool, created_at: string, updated_at: string} $row
         */
        return User::reconstitute(
            UserId::fromString($row['id']),
            $row['email'],
            $row['password_hash'],
            $row['email_verified'],
            $row['is_active'],
            Timestamp::fromDatabase($row['created_at']),
            Timestamp::fromDatabase($row['updated_at']),
        );
    }
}
