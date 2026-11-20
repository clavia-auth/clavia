<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication;

use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;

/**
 * End the browser's session and decide where it goes next.
 *
 * Unlike the target after sign-in, this one may leave the server: every application
 * signing a person out lives on its own origin. So the trust anchor moves from "this
 * server" to "an origin some client registered a redirect URI on" — the data the
 * authorization endpoint already trusts. Anything else falls back to the login page,
 * never repaired: a phishing page one character from a trusted origin is exactly what
 * partial validation lets through.
 */
final readonly class SignOut
{
    public function __construct(
        private Sessions $sessions,
        private ClientRepository $clients,
    ) {
    }

    /**
     * @param string|null $sessionId The identifier the browser's session cookie carries.
     * @param string|null $next      Where the caller asks to go afterwards.
     *
     * @return string Where to send the browser.
     */
    public function __invoke(#[\SensitiveParameter] ?string $sessionId, ?string $next): string
    {
        $this->sessions->end($sessionId);

        return $this->isTrusted($next) ? (string) $next : LocalPath::DEFAULT;
    }

    private function isTrusted(?string $next): bool
    {
        if ($next === null || $next === '') {
            return false;
        }

        try {
            $url = Url::fromString($next);
        } catch (InvalidValue) {
            return false;
        }

        return $url->isHttps() && ! $url->hasFragment() && $this->clients->registersRedirectOrigin($url->origin());
    }
}
