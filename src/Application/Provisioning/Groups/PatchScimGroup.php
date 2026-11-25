<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning\Groups;

use Clavia\Application\Provisioning\ProvisioningCaller;
use Clavia\Application\Provisioning\Users\AttributeTaken;
use Clavia\Application\Provisioning\Users\VersionMismatch;
use Clavia\Domain\Provisioning\ScimGroup;
use Clavia\Domain\Provisioning\ScimGroupResource;
use Clavia\Domain\Provisioning\ScimPatch;
use Clavia\Domain\Provisioning\ScimPatchRefused;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `PATCH /scim/v2/Groups/{id}` (RFC 7644 §3.5.2): the operations directories send for membership
 * (`add` to `members`, `remove` of `members[value eq "…"]`, a `replace` of `members` or
 * `displayName`) applied to the group as it stands, the result replacing it ({@see ReplaceScimGroup}).
 */
final readonly class PatchScimGroup
{
    public function __construct(
        private ReadScimGroups $read,
        private ReplaceScimGroup $replace,
    ) {
    }

    /**
     * @param list<string>|null $ifMatch The versions `If-Match` names; null without one.
     *
     * @throws ScimPatchRefused When an operation cannot be applied.
     * @throws InvalidValue     When the result is no acceptable group.
     */
    public function __invoke(
        ProvisioningCaller $caller,
        string $id,
        ScimPatch $patch,
        ?array $ifMatch = null,
    ): ScimGroup|AttributeTaken|VersionMismatch|null {
        $current = $this->read->find($caller, $id);
        if ($current === null) {
            return null;
        }
        if (! $current->isAt($ifMatch)) {
            return new VersionMismatch();
        }
        $patched = ScimGroupResource::fromJson($patch->applyTo($current->resource()->toJson()));

        return ($this->replace)($caller, $id, $patched, [$current->version()]);
    }
}
