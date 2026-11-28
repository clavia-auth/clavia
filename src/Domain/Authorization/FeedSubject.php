<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authorization;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Shared\InvalidValue;

/**
 * What one entry of the identity feed brings into step with Clavia, in one API's store
 * (docs/design/fine-grained-authorization.md §5.4): a person's role memberships, a role's members,
 * a deleted application's relationships, or every role's members at once.
 *
 * An entry names what changed, never the tuples to write: the sender reads Clavia as it is when it
 * sends, so an entry sent late, twice or out of order still leaves the store as Clavia says.
 */
final readonly class FeedSubject
{
    /** The whole store's role memberships, as a resync writes them. */
    public const string EVERY_ROLE = '*';

    private function __construct(
        public FeedSubjectKind $kind,
        /** The person's, the role's or the application's id; empty for every role. */
        public string $id,
    ) {
    }

    /** The roles the person holds there; every relationship naming them once the account is gone. */
    public static function user(UserId $user): self
    {
        return new self(FeedSubjectKind::User, $user->value);
    }

    /** The role's members there: none once it is deleted, or holds no permission on the API. */
    public static function role(RoleId $role): self
    {
        return new self(FeedSubjectKind::Role, $role->value);
    }

    /** Every relationship naming the application, once it is deleted. */
    public static function client(ClientId $client): self
    {
        return new self(FeedSubjectKind::Client, $client->value);
    }

    public static function everyRole(): self
    {
        return new self(FeedSubjectKind::EveryRole, '');
    }

    /**
     * @throws InvalidValue When the value is none of {@see self::toString()}'s forms.
     */
    public static function fromString(string $value): self
    {
        if ($value === self::EVERY_ROLE) {
            return self::everyRole();
        }
        [$kind, $id] = explode(':', $value, 2) + [1 => ''];

        return match ($kind) {
            FeedSubjectKind::User->value => self::user(UserId::fromString($id)),
            FeedSubjectKind::Role->value => self::role(RoleId::fromString($id)),
            FeedSubjectKind::Client->value => self::client(ClientId::fromString($id)),
            default => throw new InvalidValue('An identity feed subject is a person, a role, an application or `*`.'),
        };
    }

    /** `user:<id>`, `role:<id>`, `client:<id>`, or `*`. */
    public function toString(): string
    {
        return $this->kind === FeedSubjectKind::EveryRole ? self::EVERY_ROLE : $this->kind->value . ':' . $this->id;
    }

    public function equals(self $other): bool
    {
        return $this->kind === $other->kind && $this->id === $other->id;
    }
}
