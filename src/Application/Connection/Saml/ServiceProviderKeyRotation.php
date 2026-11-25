<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Connection\Saml;

use Clavia\Domain\Connection\Saml\ServiceProviderKeySet;
use DateTimeImmutable;

/** The step taken, when the next pair will be promoted, and every key after it. */
final readonly class ServiceProviderKeyRotation
{
    /** @param list<non-empty-string> $deleted Retired keys whose overlap was over. */
    public function __construct(
        public RotationStep $step,
        public ?DateTimeImmutable $promotesAt,
        public ServiceProviderKeySet $keys,
        public array $deleted = [],
    ) {
    }
}
