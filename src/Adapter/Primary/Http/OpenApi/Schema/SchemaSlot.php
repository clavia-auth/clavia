<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Schema;

use LogicException;

/**
 * The schema a reference points at, filled once the document is compiled.
 *
 * What lets a schema refer to itself (a tree whose nodes hold nodes) without the
 * compiler recursing forever: a reference compiles to its target's slot, and the slot
 * is filled after every schema exists.
 */
final class SchemaSlot
{
    private ?Schema $schema = null;

    public function __construct(public readonly string $pointer)
    {
    }

    public function fill(Schema $schema): void
    {
        if ($this->schema !== null) {
            throw new LogicException(sprintf("The schema at '#%s' is already compiled.", $this->pointer));
        }
        $this->schema = $schema;
    }

    public function isFilled(): bool
    {
        return $this->schema !== null;
    }

    public function schema(): Schema
    {
        return $this->schema
            ?? throw new LogicException(sprintf("The schema at '#%s' is not compiled yet.", $this->pointer));
    }
}
