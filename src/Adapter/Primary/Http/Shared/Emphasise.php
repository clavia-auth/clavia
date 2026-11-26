<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Clavia\Application\Port\Messages;
use Laminas\View\Helper\HelperInterface;

/**
 * The templates' `$this->emphasised('check_inbox.reset', ['email' => $email], 'email')`: a whole sentence
 * of the catalogue with one of its values in `<strong>`, so a translator places the value where their
 * language wants it (`{email}`) instead of translating fragments around it.
 *
 * The message holds no markup, as every message: the sentence is worded with a random marker for the
 * value, escaped whole, and only then is the marker replaced by the value, escaped, in `<strong>`. What it
 * returns is HTML, safe to print as it is; nothing in a message or a value can add markup.
 */
final readonly class Emphasise implements HelperInterface
{
    public function __construct(
        private Messages $messages,
        private PageLanguage $language,
    ) {
    }

    /**
     * @param non-empty-string                    $key
     * @param array<non-empty-string, string|int> $values
     * @param non-empty-string                    $emphasised The value shown in bold.
     */
    public function __invoke(string $key, array $values, string $emphasised): string
    {
        $marker = 'EMPHASIS' . bin2hex(random_bytes(8));
        $text = $this->messages->text(
            $this->language->current(),
            $key,
            [...$values, $emphasised => $marker],
        );

        return str_replace(
            $marker,
            '<strong>' . self::escape((string) ($values[$emphasised] ?? '')) . '</strong>',
            self::escape($text),
        );
    }

    /** As laminas-view's `escapeHtml()`: quotes too, invalid UTF-8 replaced, never passed through. */
    private static function escape(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
