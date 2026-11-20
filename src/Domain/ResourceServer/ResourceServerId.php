<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\ResourceServer;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * The identifier of a registered API: `rs_` and 16 letters and digits.
 *
 * A surrogate key by choice. The natural key is the audience identifier, a URI —
 * right as an `aud`, unwieldy as a path segment and as a key repeated on every
 * permission and grant. The id addresses the record; the identifier names the audience.
 */
final readonly class ResourceServerId
{
    private const string PREFIX = 'rs';

    /** @param non-empty-string $value */
    private function __construct(public string $value)
    {
    }

    public static function generate(SecretGenerator $secrets): self
    {
        return new self($secrets->prefixedId(self::PREFIX));
    }

    /**
     * @throws InvalidValue When the value is not `rs_` followed by 16 letters and digits.
     */
    public static function fromString(string $value): self
    {
        if ($value === '' || preg_match('/^rs_[A-Za-z0-9]{16}$/D', $value) !== 1) {
            throw new InvalidValue('A resource server id is "rs_" followed by 16 letters and digits.');
        }

        return new self($value);
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
