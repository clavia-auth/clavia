<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Connection\Saml;

/** What one call of `saml-keys:rotate` did (docs/design/saml-connections.md §5.1). */
enum RotationStep: string
{
    /** There were no keys: the first pair, current at once. */
    case Generated = 'generated';

    /** A next pair, published beside the current one, not used yet. */
    case Introduced = 'introduced';

    /** The next pair, past its overlap, made current; the pair it replaces retired. */
    case Promoted = 'promoted';

    /** A next pair is published but its overlap is not over: nothing changed. */
    case Waiting = 'waiting';
}
