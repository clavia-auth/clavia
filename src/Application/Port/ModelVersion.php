<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Authorization\AuthorizationModelId;

/**
 * One version of a store's model, as the decision engine keeps it (docs/design/fine-grained-authorization.md
 * §5.6): its id, and the model as the engine returns it, JSON text whose objects stay objects.
 *
 * It is not held again to {@see \Clavia\Domain\Authorization\AuthorizationModel}'s rules: a version
 * written under earlier ones is still shown as it is, and reading one never puts it in force.
 */
final readonly class ModelVersion
{
    public function __construct(
        public AuthorizationModelId $id,
        public string $json,
    ) {
    }
}
