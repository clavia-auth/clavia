<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\ProviderName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\AlreadyExists;
use Throwable;

/**
 * External identities in `external_identities`. The primary key decides whether a
 * subject is already linked: an insert that violates it is {@see AlreadyExists}.
 */
final readonly class PhpDbExternalIdentityRepository implements ExternalIdentityRepository
{
    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function find(ProviderName $provider, string $subject): ?ExternalIdentity
    {
        /**
         * @var array{provider: string, subject: non-empty-string, user_id: string, email: string|null,
         *     linked_at: string}|null $row
         */
        $row = $this->database->fetchOne(
            'SELECT provider, subject, user_id, email, linked_at FROM external_identities'
            . ' WHERE provider = :provider AND subject = :subject',
            ['provider' => $provider->value, 'subject' => $subject],
        );
        if ($row === null) {
            return null;
        }

        return ExternalIdentity::reconstitute(
            ProviderName::fromString($row['provider']),
            $row['subject'],
            UserId::fromString($row['user_id']),
            $row['email'],
            Timestamp::fromDatabase($row['linked_at']),
        );
    }

    #[\Override]
    public function add(ExternalIdentity $identity): void
    {
        try {
            $this->database->execute(
                'INSERT INTO external_identities (provider, subject, user_id, email, linked_at)'
                . ' VALUES (:provider, :subject, :user_id, :email, :linked_at)',
                [
                    'provider' => $identity->provider->value,
                    'subject' => $identity->subject,
                    'user_id' => $identity->userId->value,
                    'email' => $identity->email,
                    'linked_at' => Timestamp::toDatabase($identity->linkedAt),
                ],
            );
        } catch (Throwable $failure) {
            throw Constraint::isUniqueViolation($failure, 'pk_external_identities')
                ? new AlreadyExists('This identity is already linked to an account.', 0, $failure)
                : $failure;
        }
    }
}
