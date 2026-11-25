<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Provisioning;

/**
 * The attributes a SCIM filter may compare (docs/design/scim-provisioning.md §2): those directories
 * match on before they create anyone. Entra ID filters on `userName` (or `externalId`), Okta on
 * `userName`.
 */
enum ScimFilterAttribute: string
{
    /** Compared ignoring case (RFC 7643 §4.1.1: `caseExact` false). */
    case UserName = 'username';
    /** Compared exactly (RFC 7643 §3.1). */
    case ExternalId = 'externalid';
    case Id = 'id';
    /** The account's address, compared ignoring case. */
    case EmailValue = 'emails.value';
}
