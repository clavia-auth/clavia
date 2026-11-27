<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authorization;

/**
 * The types of an authorization model that are Clavia's (docs/design/fine-grained-authorization.md
 * §2, "Reserved types"): people, applications, roles and, once directories provision them, groups.
 *
 * Clavia is the source of truth for each, so an API never writes a relationship whose object is
 * one of them: `role:admin#member@user:mallory`, written by an API, would grant through the back
 * door what roles grant. A model declares `user` always, and the others when it uses them, in the
 * one shape Clavia writes ({@see AuthorizationModel}).
 */
enum ReservedType: string
{
    /** A person, `user:<user id>`: the `sub` of their tokens. Declared by every model. */
    case User = 'user';
    /** An application, `client:<client id>`. */
    case Client = 'client';
    /** A role, `role:<role id>`, whose `member`s are the people holding it. */
    case Role = 'role';
    /** A group a directory provisions, `group:<group id>`, whose `member`s are people. */
    case Group = 'group';

    /** The reserved type `type` is, or null for one of an API's own. */
    public static function of(ObjectType $type): ?self
    {
        return self::tryFrom($type->value);
    }

    /**
     * Whether the type is a subject only, with no relation of its own: nothing is ever related to
     * a person or an application as an object, so a relation there could only be a way around
     * Clavia.
     */
    public function isSubjectOnly(): bool
    {
        return $this === self::User || $this === self::Client;
    }
}
