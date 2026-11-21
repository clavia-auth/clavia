<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Audit;

/** Who acted, in the four shapes an action reaches this server in. */
enum ActorKind: string
{
    /** A person — signing in, or through an application acting for them (`client_id` then set). */
    case Person = 'person';

    /** An application acting as itself: a machine client's own token. */
    case Application = 'application';

    /** Whoever runs the server, at its console: `clavia` commands. */
    case System = 'system';

    /** Nobody known yet: a failed sign-in for an account that may not exist. */
    case Anonymous = 'anonymous';
}
