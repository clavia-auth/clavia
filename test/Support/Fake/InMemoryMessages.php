<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\Messages;
use Clavia\Domain\Shared\Language;
use Clavia\Domain\Shared\Languages;
use LogicException;
use MessageFormatter;

/**
 * The catalogue in memory: patterns by language and key, worded by ICU as the real one is, with the same
 * fallback to the default language. What it lacks is the files, which {@see MessagesContract} gives the
 * adapter instead.
 */
final class InMemoryMessages implements Messages
{
    /**
     * @param array<string, array<string, string>> $catalogues Patterns by language tag, then key.
     */
    public function __construct(
        private readonly Languages $languages,
        private readonly array $catalogues,
    ) {
    }

    #[\Override]
    public function text(Language $language, string $key, array $values = []): string
    {
        $wording = $language;
        $pattern = $this->catalogues[$language->tag][$key] ?? null;
        if ($pattern === null && ! $language->equals($this->languages->default)) {
            $wording = $this->languages->default;
            $pattern = $this->catalogues[$wording->tag][$key] ?? null;
        }
        if ($pattern === null) {
            throw new LogicException(sprintf('There is no message %s in the default language.', $key));
        }
        $text = MessageFormatter::formatMessage($wording->tag, $pattern, $values);

        return $text === false ? throw new LogicException('The message cannot be worded.') : $text;
    }
}
