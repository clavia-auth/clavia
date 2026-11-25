<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

use DateTimeImmutable;

/** Who a verified assertion says signed in, read from the signed assertion alone. */
final readonly class SamlIdentity
{
    /**
     * @param non-empty-string                         $subject Stable: the persistent `NameID` or the attribute named.
     * @param array<non-empty-string, list<string>>    $attributes String values only, by attribute name.
     * @param non-empty-string                         $assertionId For the replay cache.
     */
    public function __construct(
        public string $subject,
        public ?string $nameId,
        public ?string $nameIdFormat,
        public array $attributes,
        public string $assertionId,
        public DateTimeImmutable $validUntil,
        public DateTimeImmutable $authenticatedAt,
    ) {
    }
}
