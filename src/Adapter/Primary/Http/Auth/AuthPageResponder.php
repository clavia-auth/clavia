<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\HtmlPage;
use Clavia\Adapter\Primary\Http\Shared\PageRenderer;
use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Clavia\Adapter\Primary\Http\Shared\SetCookie;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Turns the auth surface's decisions into responses: its pages and its redirects.
 *
 * A page is rendered by {@see PageRenderer} (layout, headers, per-page CSP) with the
 * browser's CSRF token added: the token belongs to the browser, so one already held is
 * reused, and only a browser without one gets a fresh value. Minting one per render
 * would make a prefetch, a second tab or the back button invalidate the form the person
 * is looking at.
 */
final readonly class AuthPageResponder
{
    public function __construct(
        private PageRenderer $pages,
        private ResponseFactoryInterface $responses,
        private SecretGenerator $secrets,
        private AuthCookies $cookies,
    ) {
    }

    public function page(ServerRequestInterface $request, HtmlPage $page): ResponseInterface
    {
        $held = RequestCookies::all($request, AuthCookies::CSRF);
        $csrfToken = $held[0] ?? $this->secrets->token();

        $response = $this->pages
            ->render($request, $page, ['csrfToken' => $csrfToken])
            ->withAddedHeader('Set-Cookie', $this->cookies->csrf($csrfToken)->toString());

        // A second cookie of the same name lives at another path: stop the browser
        // sending a value that can never match.
        return count($held) > 1
            ? $response->withAddedHeader('Set-Cookie', $this->cookies->expireStrayCsrf()->toString())
            : $response;
    }

    /**
     * A `303 See Other` within this server or to a validated destination, with cookies.
     *
     * @param list<SetCookie> $cookies
     */
    public function redirect(string $location, array $cookies = []): ResponseInterface
    {
        $response = $this->responses->createResponse(303)
            ->withHeader('Location', $location)
            ->withHeader('Cache-Control', 'no-store');

        foreach ($cookies as $cookie) {
            $response = $response->withAddedHeader('Set-Cookie', $cookie->toString());
        }

        return $response;
    }
}
