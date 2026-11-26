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
use Clavia\Domain\Shared\Language;
use Laminas\Diactoros\Response\HtmlResponse;
use Laminas\View\Model\ViewModel;
use Mezzio\Template\TemplateRendererInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Renders an {@see HtmlPage} inside the layout every page of this server shares, with the
 * headers every one of them carries.
 *
 * - **Never cached.** Pages carry CSRF tokens, prefilled emails, and later TOTP seeds and
 *   recovery codes; an error page describes one person's request.
 * - **No script, unless the page loads one module of this server's.** `default-src 'none'`
 *   with nothing loosening it, except on a page that names its module ({@see HtmlPage::$script}):
 *   that page allows `script-src 'self'` and nothing more — no inline script, no `eval`, no other
 *   origin — and Trusted Types with no policy, so the module cannot write HTML from a string.
 *   Data for the module travels in escaped `data-` attributes, never in a script block. Styles come
 *   from `/auth/static` with no inline `style` attribute, which is what lets `style-src` stay at
 *   `'self'`.
 * - **WebAuthn on this origin only** (`Permissions-Policy`): no frame may create or use a passkey
 *   for this site, whoever embeds it.
 * - **`form-action` per page.** Every form posts to this origin, but a successful post
 *   may redirect onwards — to `/oauth2/authorize` and from there to the application's
 *   redirect URI — and Chromium applies `form-action` to a submission's whole redirect
 *   chain. A page that belongs to an authorization request therefore also lists that
 *   application's redirect origins, already trusted for exactly this by the
 *   authorization endpoint; any other page lists `'self'` alone.
 * - **Framed by nobody**, `nosniff`, and a referrer that never leaves this origin.
 */
final readonly class PageRenderer
{
    /** The colour-scheme cookie; absent means "follow the system". */
    public const string THEME_COOKIE = 'clavia_theme';

    /** The colour schemes a person can force. */
    public const array THEMES = ['light', 'dark'];

    private const array HEADERS = [
        'Cache-Control' => 'no-store',
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        'Referrer-Policy' => 'same-origin',
        'Permissions-Policy' => 'publickey-credentials-create=(self), publickey-credentials-get=(self)',
    ];

    public function __construct(
        private TemplateRendererInterface $templates,
        private LanguageChoice $choice,
        private PageLanguage $language,
        private Messages $messages,
    ) {
    }

    /**
     * @param array<non-empty-string, mixed> $variables Printed by the page template, beside the page's own.
     */
    public function render(ServerRequestInterface $request, HtmlPage $page, array $variables = []): ResponseInterface
    {
        // The page's language, for its messages here and its templates' t() (docs/design/
        // translated-sign-in-pages.md §5.1); said in <html lang> and Content-Language (RFC 9110 §8.5).
        $language = ($this->choice)($request);
        $this->language->set($language);
        $html = $this->templates->render($page->template, [
            'layout' => new ViewModel([
                'language' => $language->tag,
                'title' => $this->word($language, $page->title),
                'heading' => $this->word($language, $page->heading),
                'error' => $page->error === null ? null : $this->word($language, $page->error),
                'theme' => self::theme($request),
                'returnTo' => $page->returnTo,
                'wide' => $page->wide,
                'script' => $page->script,
            ], 'layout::page'),
            // A variable that is a message reaches its template worded.
            ...array_map(
                fn (mixed $value): mixed => $value instanceof Message ? $this->word($language, $value) : $value,
                $page->variables,
            ),
            ...$variables,
        ]);

        return new HtmlResponse(
            $html,
            $page->status,
            self::HEADERS + [
                'Content-Language' => $language->tag,
                'Content-Security-Policy' => self::policy($page->formOrigins, $page->script !== null),
            ],
        );
    }

    /** A page's message in its language. */
    private function word(Language $language, Message $message): string
    {
        return $this->messages->text($language, $message->key, $message->values);
    }

    /**
     * The forced colour scheme, or null to follow the system. A value this server did not
     * set is ignored, never printed.
     */
    private static function theme(ServerRequestInterface $request): ?string
    {
        $theme = RequestCookies::first($request, self::THEME_COOKIE);

        return in_array($theme, self::THEMES, true) ? $theme : null;
    }

    /**
     * @param list<string> $formOrigins
     */
    private static function policy(array $formOrigins, bool $script): string
    {
        $formAction = implode(' ', array_values(array_unique(["'self'", ...$formOrigins])));

        return "default-src 'none'; style-src 'self'; img-src 'self'; form-action {$formAction}; "
            . "frame-ancestors 'none'; base-uri 'none'"
            . ($script ? "; script-src 'self'; require-trusted-types-for 'script'; trusted-types 'none'" : '');
    }
}
