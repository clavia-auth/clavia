<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Claims;

/** What a custom claim is read from (docs/design/custom-claims.md §2, "Sources"). */
enum ClaimSourceKind: string
{
    case Email = 'email';
    case EmailVerified = 'email_verified';
    case Connection = 'connection';
    case ProfileField = 'profile';
    case AppMetadata = 'app_metadata';
    case Roles = 'roles';
    case Constant = 'constant';

    /** Whether the source reads a person: a machine token, with no subject, takes constants only. */
    public function readsAPerson(): bool
    {
        return $this !== self::Constant;
    }
}
