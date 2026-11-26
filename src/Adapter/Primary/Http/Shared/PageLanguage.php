<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Clavia\Domain\Shared\Language;
use LogicException;

/**
 * The language of the page being rendered, set by {@see PageRenderer} before each page and read by the
 * templates' `t()` helper ({@see Translate}), which laminas-view builds once and cannot be handed it per
 * call. Set for every render, so nothing of one page's language reaches the next.
 */
final class PageLanguage
{
    private ?Language $language = null;

    public function set(Language $language): void
    {
        $this->language = $language;
    }

    public function current(): Language
    {
        return $this->language ?? throw new LogicException('A template asked for words outside a page.');
    }
}
