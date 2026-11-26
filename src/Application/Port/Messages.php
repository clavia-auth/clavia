<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Shared\Language;

/**
 * What a person reads, in their language: a message of the catalogue, by its key, worded with its values
 * (docs/design/translated-sign-in-pages.md). The pages and the mail reach the same catalogue through this
 * port; neither knows how it is stored.
 *
 * A message missing from the default language is a defect: it throws. Missing from another, the default
 * language's message is used instead, so a page never breaks over a translation.
 */
interface Messages
{
    /**
     * @param non-empty-string                    $key    A dotted key: `login.submit`.
     * @param array<non-empty-string, string|int> $values The message's arguments, never part of its pattern.
     *
     * @throws \LogicException When the default language has no such message, or cannot word it.
     */
    public function text(Language $language, string $key, array $values = []): string;
}
