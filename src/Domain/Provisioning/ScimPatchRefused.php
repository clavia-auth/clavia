<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Provisioning;

use InvalidArgumentException;

/**
 * A `PATCH` that cannot be applied, with RFC 7644 §3.12's `scimType`: `invalidSyntax`,
 * `invalidPath` or `noTarget`. The detail names the rule, never a value.
 */
final class ScimPatchRefused extends InvalidArgumentException
{
    /** @param 'invalidSyntax'|'invalidPath'|'noTarget' $scimType */
    private function __construct(public readonly string $scimType, string $detail)
    {
        parent::__construct($detail);
    }

    public static function syntax(string $detail): self
    {
        return new self('invalidSyntax', $detail);
    }

    public static function path(string $detail): self
    {
        return new self('invalidPath', $detail);
    }

    public static function noTarget(string $detail): self
    {
        return new self('noTarget', $detail);
    }
}
