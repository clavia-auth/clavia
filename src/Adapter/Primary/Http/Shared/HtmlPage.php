<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Fig\Http\Message\StatusCodeInterface;

/**
 * A server-rendered page, ready to render: the view model a template prints from.
 *
 * Everything a template shows is decided here, by the code that builds the page;
 * templates only print and loop.
 */
final readonly class HtmlPage
{
    /**
     * @param non-empty-string               $template    A namespaced template name, `auth::login`.
     * @param Message|string                 $title       The document title, before " · Clavia": a message
     *                                                    of the catalogue, or (until every page is
     *                                                    worded through it) text.
     * @param Message|string                 $heading     The page's `<h1>`.
     * @param string|null                    $returnTo    Where the colour-scheme toggle comes back to: a
     *                                                    local path. Null leaves the toggle out.
     * @param array<non-empty-string, mixed> $variables   What the page template prints.
     * @param Message|string|null            $error       A message shown above the content.
     * @param int                            $status      The HTTP status.
     * @param list<string>                   $formOrigins Origins a form submission on this page may end
     *                                                    at, besides this server; see {@see PageRenderer}.
     * @param bool                           $wide        A wider card, for a QR code or a list of codes.
     * @param string|null                    $script      A module this server serves (`/auth/static/…`) that
     *                                                    the page loads: the only way a page runs script,
     *                                                    and what lets its CSP allow it.
     */
    public function __construct(
        public string $template,
        public Message|string $title,
        public Message|string $heading,
        public ?string $returnTo = null,
        public array $variables = [],
        public Message|string|null $error = null,
        public int $status = StatusCodeInterface::STATUS_OK,
        public array $formOrigins = [],
        public bool $wide = false,
        public ?string $script = null,
    ) {
    }
}
