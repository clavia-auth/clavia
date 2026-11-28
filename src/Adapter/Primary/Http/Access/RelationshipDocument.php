<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Access;

use Clavia\Domain\Authorization\Tuple;

/**
 * A relationship as the Authorization API and the Management API show it
 * (docs/design/fine-grained-authorization.md §5.3, §5.6): AuthZEN's `resource` and `subject`, the
 * subject's `relation` for a userset, and its `condition` when it has one.
 */
final readonly class RelationshipDocument
{
    private function __construct()
    {
    }

    /** @return array<string, mixed> */
    public static function of(Tuple $tuple): array
    {
        $subject = ['type' => $tuple->subject->object->type->value, 'id' => $tuple->subject->object->id];
        if ($tuple->subject->relation !== null) {
            $subject['relation'] = $tuple->subject->relation->name;
        }
        $document = [
            'resource' => ['type' => $tuple->object->type->value, 'id' => $tuple->object->id],
            'relation' => $tuple->relation->name,
            'subject' => $subject,
        ];
        if ($tuple->condition !== null) {
            $document['condition'] = ['name' => $tuple->condition->name];
            if ($tuple->condition->context !== []) {
                $document['condition']['context'] = $tuple->condition->context;
            }
        }

        return $document;
    }
}
