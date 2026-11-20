<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi;

use stdClass;

/**
 * Local references (`$ref: '#/components/schemas/User'`) within one document.
 *
 * Only references into the same document are followed: one that names another file or
 * a URL is refused, so loading a document never reads anything else. A reference has
 * no siblings (OpenAPI 3.0 ignores them, which would hide a mistake), and a chain of
 * references that comes back on itself is refused.
 */
final readonly class References
{
    public function __construct(private Node $root)
    {
    }

    /** Whether `$node` is a Reference Object. */
    public static function isReference(Node $node): bool
    {
        return $node->has('$ref');
    }

    /**
     * The node `$node` stands for: itself, or what its reference — and the references
     * that one makes, in turn — point at.
     *
     * @throws InvalidDocument
     */
    public function resolve(Node $node): Node
    {
        $seen = [];
        while (self::isReference($node)) {
            $target = $this->target($node);
            if (isset($seen[$target])) {
                throw $node->invalid('is a circular reference');
            }
            $seen[$target] = true;
            $node = $this->at($target, $node);
        }

        return $node;
    }

    /**
     * The pointer a Reference Object names, checked.
     *
     * @throws InvalidDocument
     */
    public function target(Node $reference): string
    {
        foreach ($reference->names() as $name) {
            if ($name !== '$ref') {
                throw InvalidDocument::at(JsonPointer::append($reference->pointer, $name), 'cannot sit beside $ref');
            }
        }

        $ref = $reference->member('$ref')->string();
        if (! str_starts_with($ref, '#/')) {
            throw $reference->invalid(sprintf(
                "refers outside the document ('%s'): only local references are followed",
                $ref,
            ));
        }

        return rawurldecode(substr($ref, 1));
    }

    /**
     * The node at `$pointer`; `$from` is the reference that named it, for the message.
     *
     * @throws InvalidDocument When nothing is there.
     */
    public function at(string $pointer, Node $from): Node
    {
        $node = $this->root;
        foreach (JsonPointer::tokens($pointer) as $token) {
            $next = $node->value instanceof stdClass ? $node->optional($token) : null;
            if ($next === null && is_array($node->value) && ctype_digit($token)) {
                $next = $node->items()[(int) $token] ?? null;
            }
            $node = $next ?? throw $from->invalid(sprintf("refers to '#%s', which does not exist", $pointer));
        }

        return $node;
    }
}
