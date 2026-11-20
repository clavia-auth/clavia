<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Validation;

use Clavia\Adapter\Primary\Http\OpenApi\Schema\SchemaViolation;

/**
 * One way a request or a response departs from the document: where, and why.
 *
 * - In the body: {@see self::$pointer} is an RFC 6901 pointer into it (`''` for the body
 *   itself), {@see self::$name} is null.
 * - In a parameter or a header: {@see self::$name} is its name, and the pointer reaches
 *   into its value when that is an array (`/2`).
 *
 * The message never repeats the value at fault ({@see SchemaViolation}).
 */
final readonly class Violation
{
    public function __construct(
        public Location $location,
        public ?string $name,
        public string $pointer,
        public string $message,
    ) {
    }

    public static function inBody(string $pointer, string $message): self
    {
        return new self(Location::Body, null, $pointer, $message);
    }

    public static function inParameter(Location $location, string $name, string $message, string $pointer = ''): self
    {
        return new self($location, $name, $pointer, $message);
    }

    /**
     * The schema's complaints about a value found at `$location`.
     *
     * @param list<SchemaViolation> $violations
     *
     * @return list<self>
     */
    public static function fromSchema(Location $location, ?string $name, array $violations): array
    {
        return array_map(
            static fn (SchemaViolation $violation): self
                => new self($location, $name, $violation->pointer, $violation->message),
            $violations,
        );
    }

    /** `body /password: Must be at least 8 characters long.`, for logs and test failures. */
    public function describe(): string
    {
        $where = $this->location->value
            . ($this->name === null ? '' : ' ' . $this->name)
            . ($this->pointer === '' ? '' : ' ' . $this->pointer);

        return $where . ': ' . $this->message;
    }
}
