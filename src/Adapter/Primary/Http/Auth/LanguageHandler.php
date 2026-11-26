<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\LanguageChoice;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Domain\Authentication\LocalPath;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /auth/language` — remember the language a person chose, and go back to the page they chose it on
 * (docs/design/translated-sign-in-pages.md §5.4). The choice outranks what the application asks for
 * (`ui_locales`) and what the browser says (`Accept-Language`): it is the way out for a person on
 * someone else's browser, or whose application guessed wrong.
 *
 * As the colour-scheme toggle: a form post, since the pages run no script; no CSRF token, since a
 * `SameSite=Lax` cookie never rides a cross-site POST and the worst a forged one does is change how this
 * browser reads. Only an offered language, exactly as offered, is remembered; anything else changes
 * nothing. `return_to` becomes a `Location`, so it is held to the rule every other one is: a local path,
 * or the login page.
 *
 * This decides nothing about the protocol, so there is no use case behind it.
 */
final readonly class LanguageHandler implements RequestHandlerInterface
{
    public function __construct(
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
        private LanguageChoice $choice,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $form = RequestParameterReader::form($request);
        $asked = $form->get('language');
        $cookies = [];
        foreach ($this->choice->offered() as $language) {
            if ($language->tag === $asked) {
                $cookies[] = $this->cookies->language($language);
            }
        }

        return $this->responder->redirect(LocalPath::orDefault($form->get('return_to'))->value, $cookies);
    }
}
