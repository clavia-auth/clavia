<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi;

use Clavia\Adapter\Primary\Http\OpenApi\Schema\Schema;

/**
 * A Content map (OpenAPI 3.0 §4.7.10): the media types a body may have, each with the
 * schema it must satisfy. A JSON body is parsed and validated; a request's form is read as named
 * strings and validated ({@see Validation\FormBody}); anything else is opaque bytes, and said so
 * (`{type: string, format: binary}`), so nothing passes as checked that was not.
 */
final readonly class Content
{
    /**
     * @param array<string, array{MediaType, Schema|null}> $entries By media range as written.
     */
    public function __construct(private array $entries)
    {
    }

    public function isEmpty(): bool
    {
        return $this->entries === [];
    }

    /**
     * The entry for a body of type `$type`: the most specific range covering it.
     *
     * @return array{MediaType, Schema|null}|null
     */
    public function for(MediaType $type): ?array
    {
        $best = null;
        foreach ($this->entries as $entry) {
            if ($entry[0]->covers($type) && ($best === null || $entry[0]->specificity() > $best[0]->specificity())) {
                $best = $entry;
            }
        }

        return $best;
    }

    /** @return list<string> The media ranges, as written — for a 415's message. */
    public function mediaTypes(): array
    {
        return array_keys($this->entries);
    }
}
