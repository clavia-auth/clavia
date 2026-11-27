<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Http\Message\ResponseInterface;

/**
 * What acceptance tests of the sign-in need on top of {@see OAuth2Fixtures}: posting the
 * login form as a browser would, and looking at what it left behind.
 *
 * @psalm-require-extends AcceptanceTestCase
 */
trait LoginFixtures
{
    /**
     * Fetch the form, then post credentials with the CSRF token it carries — the cookie
     * set by the GET is in the jar, so it goes with the POST, as in a browser.
     *
     * The target after sign-in lives server-side behind an opaque handle. Pass `$nextUrl`
     * to have one stored ("I want to land here"); pass `$state` when the test already
     * holds a real handle — one `/oauth2/authorize` produced.
     */
    protected function submitLogin(
        string $email = self::TEST_USER_EMAIL,
        string $password = self::TEST_USER_PASSWORD,
        ?string $nextUrl = null,
        ?string $state = null,
        ?string $csrfToken = null,
    ): ResponseInterface {
        if ($nextUrl !== null) {
            $state = $this->storeLoginState($nextUrl);
        }

        $page = $this->get('/auth/login', $state === null ? [] : ['state' => $state]);

        return $this->post('/auth/login', [
            'email' => $email,
            'password' => $password,
            'csrf_token' => $csrfToken ?? self::csrfTokenFrom($page),
            'state' => $state ?? '',
        ]);
    }

    protected static function csrfTokenFrom(ResponseInterface $page): string
    {
        self::assertSame(1, preg_match('/name="csrf_token" value="([^"]+)"/', (string) $page->getBody(), $match));

        return $match[1];
    }

    /** Park a sign-in target, as `/oauth2/authorize` does, and return its handle. */
    protected function storeLoginState(string $nextUrl, ?string $clientId = null): string
    {
        /** @var SecretGenerator $secrets */
        $secrets = $this->container()->get(SecretGenerator::class);
        /** @var LoginStateStore $store */
        $store = $this->container()->get(LoginStateStore::class);

        $handle = $secrets->token();
        $store->put($handle, new LoginState($nextUrl, $clientId === null ? null : ClientId::fromString($clientId)));

        return $handle;
    }

    /** Let a held request go, as its lifetime running out would: the page opened for it stays open. */
    protected function forgetLoginState(string $handle): void
    {
        /** @var LoginStateStore $store */
        $store = $this->container()->get(LoginStateStore::class);
        $store->forget($handle);
    }

    protected function loginState(string $handle): ?LoginState
    {
        /** @var LoginStateStore $store */
        $store = $this->container()->get(LoginStateStore::class);

        return $store->get($handle);
    }

    /** The session an identifier names, if current — as the server would resolve it. */
    protected function session(?string $sessionId): ?Session
    {
        /** @var Sessions $sessions */
        $sessions = $this->container()->get(Sessions::class);

        return $sessions->resolve($sessionId);
    }
}
