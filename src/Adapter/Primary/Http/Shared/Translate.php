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
 * The templates' `$this->t('login.submit')`: a message of the catalogue in the page's language, as text
 * to escape like any other (`$this->escapeHtml($this->t(…))`): a message never holds markup.
 */
final readonly class Translate implements HelperInterface
{
    public function __construct(
        private Messages $messages,
        private PageLanguage $language,
    ) {
    }

    /**
     * @param non-empty-string                    $key
     * @param array<non-empty-string, string|int> $values
     */
    public function __invoke(string $key, array $values = []): string
    {
        return $this->messages->text($this->language->current(), $key, $values);
    }
}
