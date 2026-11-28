<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authorization;

use Clavia\Domain\Shared\InvalidValue;

/**
 * A condition a relationship holds under (OpenFGA's conditional relationship tuples): the name of a
 * condition the model declares, and the values of its parameters stored with the tuple. At question
 * time the engine evaluates it with these and the question's own context; a relationship whose
 * condition does not hold grants nothing.
 *
 * Whether the model declares it, and takes it on that relation, is the engine's to say when the tuple
 * is written.
 */
final readonly class Condition
{
    /** OpenFGA's rule for a condition's name. */
    private const string NAME = '/^[^:#@\s]{1,50}$/D';

    /** The largest context kept with one relationship, in bytes of JSON. */
    public const int MAX_CONTEXT_BYTES = 4096;

    /**
     * @param non-empty-string $name
     * @param array<string, mixed> $context The parameters' values, a JSON object.
     */
    private function __construct(
        public string $name,
        public array $context,
    ) {
    }

    /**
     * @param array<string, mixed> $context
     *
     * @throws InvalidValue When the name is not one OpenFGA takes, or the context is larger than 4 KiB.
     */
    public static function of(string $name, array $context = []): self
    {
        if ($name === '' || preg_match(self::NAME, $name) !== 1) {
            throw new InvalidValue('A condition is named by 1 to 50 characters, without ":", "#", "@" or a space.');
        }
        if (strlen(json_encode($context, JSON_THROW_ON_ERROR)) > self::MAX_CONTEXT_BYTES) {
            throw new InvalidValue('A condition\'s context is at most 4 KiB of JSON.');
        }

        return new self($name, $context);
    }
}
