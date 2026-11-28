<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Search;

/**
 * A search, as AuthZEN 1.0 §8 asks it: the entities of a question with the one being searched for left
 * out (a subject's or a resource's `id`, or the action), and how much to return. Kept as it was sent;
 * {@see SearchAccess} holds it to the model.
 */
final readonly class SearchRequest
{
    /**
     * @param array<string, mixed> $context
     * @param positive-int $limit The most results a page holds (`page.limit`).
     * @param string $pageToken The previous page's `next_token`, '' for the first.
     */
    public function __construct(
        public string $subjectType,
        public string $subjectId,
        public string $action,
        public string $resourceType,
        public string $resourceId,
        public array $context,
        public int $limit,
        public string $pageToken = '',
    ) {
    }

    /**
     * What makes the search the same search from one page to the next (§8.2: everything but the
     * token), as a digest a page token carries.
     */
    public function fingerprint(SearchKind $kind): string
    {
        return hash('sha256', json_encode([
            $kind->value,
            $this->subjectType,
            $this->subjectId,
            $this->action,
            $this->resourceType,
            $this->resourceId,
            $this->context,
            $this->limit,
        ], JSON_THROW_ON_ERROR));
    }
}
