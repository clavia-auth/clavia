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
 * The SCIM attribute (RFC 7643 §3.1, §4.1.1) that names a provisioned person to their enterprise
 * connection: the subject their first SAML or OpenID Connect sign-in is found by
 * (docs/design/scim-provisioning.md §2).
 *
 * Entra ID maps `externalId` (by default from `mailNickname`; operators map it from the object id
 * its SAML `objectidentifier` claim carries). Okta sends its login as `userName`.
 */
enum SubjectAttribute: string
{
    case ExternalId = 'externalId';
    case UserName = 'userName';
}
