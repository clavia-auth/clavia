<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ProvisioningTokens;

use Clavia\Domain\Provisioning\ProvisioningToken;
use Clavia\Domain\Provisioning\SubjectAttribute;

/**
 * What an operator asks for when issuing a provisioning token (docs/design/scim-provisioning.md §5.1).
 */
final readonly class NewProvisioningToken
{
    /**
     * @param string           $connection        The pool or enterprise connection the directory provisions.
     * @param string           $description       Which directory it is for, 1 to 120 bytes.
     * @param int              $lifetimeSeconds   A day to two years; a year by default.
     * @param SubjectAttribute $subjectAttribute  What names a person to an enterprise connection.
     * @param bool             $addressesTrusted  Whether the directory's addresses are taken as verified.
     * @param bool             $deleteDeactivates Whether a SCIM `DELETE` deactivates rather than deletes.
     */
    public function __construct(
        public string $connection,
        public string $description,
        public int $lifetimeSeconds = ProvisioningToken::DEFAULT_LIFETIME_SECONDS,
        public SubjectAttribute $subjectAttribute = SubjectAttribute::ExternalId,
        public bool $addressesTrusted = false,
        public bool $deleteDeactivates = false,
    ) {
    }
}
