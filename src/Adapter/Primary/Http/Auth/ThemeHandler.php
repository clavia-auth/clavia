<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Domain\Authentication\LocalPath;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /auth/theme` — remember a colour scheme and go back to the page it was set from.
 *
 * A form post because the pages have no script to flip a class with, and a POST because
 * it writes a cookie. No CSRF token: the worst a cross-site post can do is change the
 * victim's colour scheme. `next` becomes a `Location`, so it is held to the same rule as
 * every other one: a local path, or the login page.
 *
 * This decides nothing about the protocol, so there is no use case behind it.
 */
final readonly class ThemeHandler implements RequestHandlerInterface
{
    public function __construct(
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $form = RequestParameterReader::form($request);
        $theme = $form->get('theme');

        return $this->responder->redirect(
            LocalPath::orDefault($form->get('next'))->value,
            // Anything but a known scheme — the explicit "auto" included — means follow the system.
            [
                in_array($theme, AuthCookies::THEMES, true)
                    ? $this->cookies->theme($theme)
                    : $this->cookies->expireTheme(),
            ],
        );
    }
}
