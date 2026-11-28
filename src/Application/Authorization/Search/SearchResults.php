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
 * One page of a search (AuthZEN 1.0 §8.3): the subjects' or resources' ids, or the actions' names, of
 * the type searched for; the token of the next page, '' after the last (§8.2.2). A search the engine
 * refuses to evaluate (a condition reading a parameter that is not there) has no results and says why,
 * failing closed.
 */
final readonly class SearchResults
{
    /**
     * @param list<string> $ids
     */
    public function __construct(
        public array $ids,
        public string $nextToken,
        public ?string $error = null,
    ) {
    }

    public static function none(?string $error = null): self
    {
        return new self([], '', $error);
    }
}
