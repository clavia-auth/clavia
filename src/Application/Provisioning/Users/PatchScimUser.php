<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning\Users;

use Clavia\Application\Provisioning\ProvisioningCaller;
use Clavia\Domain\Provisioning\ScimPatch;
use Clavia\Domain\Provisioning\ScimPatchRefused;
use Clavia\Domain\Provisioning\ScimUser;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `PATCH /scim/v2/Users/{id}` (RFC 7644 §3.5.2; docs/design/scim-provisioning.md §5.3): the
 * operations applied to the resource as it stands, and the result held to the rules of a whole
 * replacement ({@see ReplaceScimUser}), so a `PATCH` can do nothing a `PUT` could not.
 */
final readonly class PatchScimUser
{
    public function __construct(
        private ReadScimUsers $read,
        private ReplaceScimUser $replace,
    ) {
    }

    /**
     * @param list<string>|null $ifMatch The versions `If-Match` names; null without one.
     *
     * @return ProvisionedUser|AttributeTaken|VersionMismatch|null Null when the connection has no such account.
     *
     * @throws ScimPatchRefused When an operation cannot be applied.
     * @throws InvalidValue     When the result is no acceptable resource.
     */
    public function __invoke(
        ProvisioningCaller $caller,
        string $id,
        ScimPatch $patch,
        ?array $ifMatch = null,
    ): ProvisionedUser|AttributeTaken|VersionMismatch|null {
        $current = $this->read->find($caller, $id);
        if ($current === null) {
            return null;
        }
        if (! $current->isAt($ifMatch)) {
            return new VersionMismatch();
        }
        $patched = ScimUser::fromJson($patch->applyTo(ScimUser::of($current->user, $current->account)->toJson()));

        // The version just checked: a change between the two reads is caught by the replacement.
        return ($this->replace)($caller, $id, $patched, [$current->version()]);
    }
}
