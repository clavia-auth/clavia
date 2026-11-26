<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\UiLocales;

/**
 * Where a browser sent to the login page goes once it has signed in.
 *
 * `/oauth2/authorize` sends an unauthenticated browser to sign in, and the place to
 * come back to is a real, already-validated authorization request: `client_id`,
 * `redirect_uri`, `code_challenge`, `state`. A `next=…` query parameter would carry all
 * of that through browser history, every access-log line of the login page and any
 * `Referer` a subresource happened to send. So the target is kept server-side and only
 * an opaque handle travels.
 *
 * Whatever a handle resolves to is still re-validated before it is used as a redirect
 * target: the store keeps the value out of URLs, it is not a reason to trust it.
 */
final readonly class LoginState
{
    /**
     * Long enough that a login tab left open over a coffee still knows where to go back
     * to, short enough that an abandoned authorization attempt does not linger. Not
     * extended on read: the window is for finishing this sign-in.
     */
    public const int LIFETIME_SECONDS = 3600;

    /** The languages the request asked its pages in (`ui_locales`); none if none. */
    public UiLocales $uiLocales;

    /**
     * @param string         $nextUrl   A same-origin path and query: the authorization request to resume.
     * @param ClientId|null  $clientId  The application the sign-in is for, so the login page can offer
     *                                  only the ways of signing in that application enables; null for a
     *                                  page reached directly.
     * @param UiLocales|null $uiLocales The languages the request asked its pages in: none when it asked for
     *                                  none, or there was no request.
     */
    public function __construct(
        public string $nextUrl,
        public ?ClientId $clientId = null,
        ?UiLocales $uiLocales = null,
    ) {
        $this->uiLocales = $uiLocales ?? UiLocales::none();
    }
}
