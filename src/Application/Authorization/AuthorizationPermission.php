<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization;

/**
 * The permissions of the Authorization API (docs/design/fine-grained-authorization.md §2, "Who
 * calls"): what an API's own client may ask of the policy decision point, granted from the shell
 * (`clients:grant`) like every client grant, so no endpoint can widen them.
 *
 * Each is confined to the one API the client speaks for.
 */
enum AuthorizationPermission: string
{
    /** AuthZEN's access evaluation and evaluations: "may this subject do this to that?" */
    case EvaluateAccess = 'evaluate:access';
    /** AuthZEN's subject, resource and action search. */
    case SearchAccess = 'search:access';
    /** Writing and reading the relationships of the API's own resources. */
    case WriteRelationships = 'write:relationships';

    /** A sentence for the permission, shown wherever one is assigned. */
    public function description(): string
    {
        return match ($this) {
            self::EvaluateAccess => 'Ask whether a subject may act on a resource',
            self::SearchAccess => 'Search the subjects, resources and actions a decision allows',
            self::WriteRelationships => 'Write and read the relationships of the API\'s resources',
        };
    }
}
