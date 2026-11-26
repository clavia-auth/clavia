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
use Locale;
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
        private StaticAssets $assets = new StaticAssets(),
        private ?BrandingChoice $branding = null,
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
                'languages' => $this->switcher(),
                'wide' => $page->wide,
                'script' => $page->script === null ? null : $this->assets->url($page->script),
                'stylesheet' => $this->assets->url('/auth/static/auth.css'),
                'icon' => $this->assets->url('/auth/static/clavia-icon.svg'),
                'brand' => self::brand($this->branding, $request),
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

    /**
     * The language a page for this request is shown in: what the mail a person causes from it is in too
     * (docs/design/translated-sign-in-pages.md §5.3).
     */
    public function language(ServerRequestInterface $request): Language
    {
        return ($this->choice)($request);
    }

    /**
     * The switcher's choices: each offered language named in itself (an endonym, from ICU), since a person
     * who cannot read the page's language must still find their own. None when only one is offered.
     *
     * @return array<string, string> Tag => name.
     */
    private function switcher(): array
    {
        $offered = $this->choice->offered();
        if (count($offered) < 2) {
            return [];
        }
        $names = [];
        foreach ($offered as $language) {
            $name = Locale::getDisplayName($language->tag, $language->tag);
            $names[$language->tag] = mb_strtoupper(mb_substr($name, 0, 1)) . mb_substr($name, 1);
        }

        return $names;
    }

    /**
     * The look of the application the page serves, for the layout; null for this server's own.
     *
     * @return array{name: string, logo: string|null, style: string|null}|null
     */
    private static function brand(?BrandingChoice $choice, ServerRequestInterface $request): ?array
    {
        $branding = $choice === null ? null : $choice($request);

        return $branding === null ? null : BrandingChoice::view($branding);
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
