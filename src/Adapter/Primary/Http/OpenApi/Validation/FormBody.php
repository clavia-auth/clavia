<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Validation;

use Clavia\Adapter\Primary\Http\OpenApi\JsonPointer;
use stdClass;

/**
 * An `application/x-www-form-urlencoded` body (WHATWG URL §5.1), read as a query string is
 * ({@see QueryString}: every name as sent, `+` a space), and handed to the schema as a JSON object
 * of strings, which is all a form can carry.
 *
 * A field sent twice is malformed, never "the last one wins": RFC 6749 §3.1 forbids repeating a
 * parameter at the endpoints that take forms, and the server refuses it there. A name or value that
 * is not UTF-8 once decoded is malformed too.
 */
final readonly class FormBody
{
    /**
     * @param stdClass        $values    Each field, by name, as a string; empty when malformed.
     * @param list<Violation> $malformed What makes the body unreadable, each at its field.
     */
    private function __construct(
        public stdClass $values,
        public array $malformed,
    ) {
    }

    public static function read(string $raw): self
    {
        $form = QueryString::parse($raw);
        if ($form === null) {
            return new self(new stdClass(), [Violation::inBody('', 'Is not valid UTF-8.')]);
        }

        $values = new stdClass();
        $malformed = [];
        foreach ($form->names() as $name) {
            $sent = $form->values($name);
            if (count($sent) !== 1) {
                $malformed[] = Violation::inBody(JsonPointer::append('', $name), 'Is sent more than once.');
                continue;
            }
            $values->{$name} = $sent[0];
        }

        return new self($malformed === [] ? $values : new stdClass(), $malformed);
    }
}
