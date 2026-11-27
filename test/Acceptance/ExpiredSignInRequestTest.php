<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\InitiateLoginUri;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A sign-in whose held request is gone sends the person back to the application (#219): to its
 * `initiate_login_uri` (OpenID Connect Dynamic Client Registration 1.0 §2, Core 1.0 §4), which an
 * operator registers, with `iss`. The store remembers which application the request was for a day
 * after the request itself; without that, or without an address, the "Sign-in expired" page (#218).
 */
final class ExpiredSignInRequestTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string START = 'https://client.test/sign-in?from=clavia';
    private const string BACK_TO_THE_APPLICATION = self::START . '&iss=https%3A%2F%2Fauth.clavia.test';

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->user();
        $this->publicClient();
    }

    // ── Registering it ──────────────────────────────────────────────────────────

    public function testAnOperatorSetsAndClearsIt(): void
    {
        $this->adminToken();

        $set = $this->patchClient(['initiate_login_uri' => self::START]);
        self::assertSame(StatusCodeInterface::STATUS_OK, $set->getStatusCode(), (string) $set->getBody());
        self::assertSame(self::START, self::document($set)['initiate_login_uri']);

        $cleared = $this->patchClient(['initiate_login_uri' => null]);
        self::assertSame(StatusCodeInterface::STATUS_OK, $cleared->getStatusCode(), (string) $cleared->getBody());
        self::assertNull(self::document($cleared)['initiate_login_uri']);
    }

    public function testAClientIsRegisteredWithIt(): void
    {
        $this->adminToken();

        $created = $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/clients', [
            'name' => 'Acme Reports',
            'redirect_uris' => ['https://reports.example.com/callback'],
            'initiate_login_uri' => 'https://reports.example.com/sign-in',
        ]);

        self::assertSame(StatusCodeInterface::STATUS_CREATED, $created->getStatusCode(), (string) $created->getBody());
        self::assertSame('https://reports.example.com/sign-in', self::document($created)['initiate_login_uri']);
    }

    /** Registration §2: it MUST use the https scheme; and a fragment would swallow `iss`. */
    public function testOnlyAnHttpsAddressWithoutAFragmentIsTaken(): void
    {
        $this->adminToken();

        foreach (['http://client.test/sign-in', 'https://client.test/sign-in#here', 'not a url'] as $refused) {
            self::assertSame(
                StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
                $this->patchClient(['initiate_login_uri' => $refused])->getStatusCode(),
                $refused,
            );
        }
        self::assertNull($this->client()->initiateLoginUri);
    }

    // ── Sent back to it ─────────────────────────────────────────────────────────

    /** The tab sat open past the hour and the password is right: the application starts a new request. */
    public function testAPasswordAfterTheRequestExpiredSendsThePersonToTheApplication(): void
    {
        $this->startsSignInsAt(self::START);
        $state = $this->heldRequest();
        $page = $this->get('/auth/login', ['state' => $state]);
        $this->forgetLoginState($state);

        $response = $this->post('/auth/login', [
            'email' => self::TEST_USER_EMAIL,
            'password' => self::TEST_USER_PASSWORD,
            'csrf_token' => self::csrfTokenFrom($page),
            'state' => $state,
        ]);

        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        self::assertSame(self::BACK_TO_THE_APPLICATION, $response->getHeaderLine('Location'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertNull(self::setCookieHeader($response, 'clavia_session'), 'Nobody was signed in.');
    }

    /** The page loaded after the hour goes straight back, as does the "please try again" of an expired form. */
    public function testThePageForAnExpiredRequestSendsThePersonToTheApplication(): void
    {
        $this->startsSignInsAt(self::START);
        $state = $this->heldRequest();
        $this->forgetLoginState($state);

        $page = $this->get('/auth/login', ['state' => $state]);
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $page->getStatusCode());
        self::assertSame(self::BACK_TO_THE_APPLICATION, $page->getHeaderLine('Location'));

        $expiredForm = $this->post('/auth/login', [
            'email' => self::TEST_USER_EMAIL,
            'password' => self::TEST_USER_PASSWORD,
            'csrf_token' => 'from-a-cookie-long-gone',
            'state' => $state,
        ]);
        self::assertSame(self::BACK_TO_THE_APPLICATION, $expiredForm->getHeaderLine('Location'));
    }

    public function testEveryOtherWayInSendsThePersonBackToo(): void
    {
        $this->startsSignInsAt(self::START);
        $state = $this->heldRequest();
        $page = $this->get('/auth/login', ['state' => $state]);
        $this->forgetLoginState($state);
        $pool = $this->container()->get(ConnectionRepository::class)->find(ConnectionName::defaultPool());
        self::assertNotNull($pool);
        $this->container()->get(ConnectionRepository::class)->save($pool->switched(null, null, null, true, false));

        $answers = [
            'sign-up page' => $this->get('/auth/signup', ['state' => $state]),
            'sign-up' => $this->post('/auth/signup', [
                'email' => 'new@example.com',
                'password' => 'a long enough password',
                'csrf_token' => self::csrfTokenFrom($page),
                'state' => $state,
            ]),
            'email code' => $this->post('/auth/passwordless/start', [
                'email' => 'new@example.com',
                'mode' => 'code',
                'csrf_token' => self::csrfTokenFrom($page),
                'state' => $state,
            ]),
        ];

        foreach ($answers as $what => $answer) {
            self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $answer->getStatusCode(), $what);
            self::assertSame(self::BACK_TO_THE_APPLICATION, $answer->getHeaderLine('Location'), $what);
        }
    }

    /** Without an address there is nowhere to send them: they are told to go back. */
    public function testAnApplicationWithoutAnAddressGetsTheExpiredPage(): void
    {
        $state = $this->heldRequest();
        $this->forgetLoginState($state);

        $page = $this->get('/auth/login', ['state' => $state]);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $page->getStatusCode());
        self::assertStringContainsString('Sign-in expired', (string) $page->getBody());
    }

    /**
     * Which application is the store's memory, never the request's say: a handle this server never
     * handed out sends nobody anywhere, whatever applications have an address.
     */
    public function testAHandleNeverHandedOutSendsNobodyAnywhere(): void
    {
        $this->startsSignInsAt(self::START);

        $page = $this->get('/auth/login', ['state' => 'forged', 'client_id' => self::TEST_CLIENT_ID]);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $page->getStatusCode());
        self::assertSame('', $page->getHeaderLine('Location'));
    }

    /**
     * Chromium applies `form-action` to a form's whole redirect chain: a page whose submit may end at the
     * application's sign-in address names its origin, beside the redirect URIs'.
     */
    public function testTheLoginPageLetsASubmitEndAtTheApplicationsSignInAddress(): void
    {
        $this->startsSignInsAt('https://start.client.test/sign-in');

        $page = $this->get('/auth/login', ['state' => $this->heldRequest()]);

        self::assertStringContainsString(
            "form-action 'self' https://client.test https://start.client.test;",
            $page->getHeaderLine('Content-Security-Policy'),
        );
    }

    private function heldRequest(): string
    {
        $asked = $this->get('/oauth2/authorize', $this->authorizeParams($this->makePkcePair()[1]));
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $asked->getStatusCode(), (string) $asked->getBody());

        return self::locationQuery($asked)['state'];
    }

    private function startsSignInsAt(string $address): void
    {
        $clients = $this->container()->get(ClientRepository::class);
        $clients->save($this->client()->withInitiateLoginUri(InitiateLoginUri::fromString($address)));
    }

    private function client(): Client
    {
        $client = $this->container()->get(ClientRepository::class)->find(ClientId::fromString(self::TEST_CLIENT_ID));
        self::assertNotNull($client);

        return $client;
    }

    /** @param array<string, mixed> $changes */
    private function patchClient(array $changes): ResponseInterface
    {
        return $this->api(RequestMethodInterface::METHOD_PATCH, '/api/v1/clients/' . self::TEST_CLIENT_ID, $changes);
    }
}
