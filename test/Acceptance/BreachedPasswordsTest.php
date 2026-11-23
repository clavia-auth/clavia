<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Secondary\BreachedPasswords\PwnedPasswordsRange;
use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Application\Port\MailOutbox;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\Fake\PwnedPasswordsService;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Laminas\Diactoros\Response\TextResponse;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Breached passwords (NIST SP 800-63B §5.1.1.2): with `CLAVIA_BREACHED_PASSWORD_CHECK` on,
 * a password found in Have I Been Pwned's Pwned Passwords is refused wherever one is chosen —
 * signing up, resetting, an operator setting one — and the check fails open.
 *
 * The service is a fake answering as the real one does ({@see PwnedPasswordsService}), and
 * the outbound policy resolves its name to a public address without asking DNS.
 */
final class BreachedPasswordsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string EMAIL = 'grace@clavia.dev';

    /** In every breach corpus there is. */
    private const string BREACHED = 'password123';

    private const string GOOD = 'correct horse battery';

    private FakeHttpClient $service;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new FakeHttpClient(PwnedPasswordsService::knowing([self::BREACHED]));
    }

    public function testTheCheckIsOffByDefaultAndNothingLeavesTheServer(): void
    {
        $this->install();
        $this->openSignUp();

        $response = $this->signUp(self::BREACHED);

        self::assertSame(303, $response->getStatusCode(), (string) $response->getBody());
        self::assertNotNull($this->account());
        self::assertSame([], $this->service->requests);
    }

    public function testABreachedPasswordIsRefusedAtSignUp(): void
    {
        $this->checkOn();
        $this->openSignUp();

        $response = $this->signUp(self::BREACHED);

        self::assertSame(400, $response->getStatusCode());
        self::assertStringContainsString('appeared in a data breach', (string) $response->getBody());
        self::assertNull($this->account());
        // k-anonymity: the first five characters of the SHA-1, and nothing more.
        self::assertCount(1, $this->service->requests);
        self::assertSame(
            '/range/' . substr(PwnedPasswordsRange::hashOf(self::BREACHED), 0, 5),
            $this->service->requests[0]->getUri()->getPath(),
        );
    }

    public function testAnotherPasswordSignsUpAsBefore(): void
    {
        $this->checkOn();
        $this->openSignUp();

        self::assertSame(303, $this->signUp(self::GOOD)->getStatusCode());
        self::assertNotNull($this->account());
    }

    public function testWhenTheServiceIsDownThePasswordIsLetThroughAndTheOutageLogged(): void
    {
        $this->service->answerWith(static fn (): ResponseInterface => new TextResponse('', 503));
        $this->checkOn();
        $this->openSignUp();

        $response = $this->signUp(self::BREACHED);

        self::assertSame(303, $response->getStatusCode(), (string) $response->getBody());
        self::assertNotNull($this->account());
        self::assertTrue($this->logger->hasRecordContaining('answered 503'));
    }

    public function testABreachedPasswordIsRefusedAtAResetAndTheLinkKept(): void
    {
        $this->checkOn();
        $this->openSignUp();
        $this->signUp(self::GOOD);
        $this->clearCookies();
        $this->post('/auth/password/forgot', [
            'email' => self::EMAIL,
            'csrf_token' => self::csrfTokenFrom($this->get('/auth/password/forgot')),
            'state' => '',
        ]);
        $link = $this->resetLink();
        $form = $this->get($link);

        $refused = $this->post('/auth/password/reset', [
            'token' => self::tokenOf($link),
            'password' => self::BREACHED,
            'csrf_token' => self::csrfTokenFrom($form),
        ]);

        self::assertSame(400, $refused->getStatusCode());
        self::assertStringContainsString('appeared in a data breach', (string) $refused->getBody());
        self::assertSame(200, $this->get($link)->getStatusCode(), 'The link is still good.');
    }

    public function testAnOperatorCannotSetABreachedPassword(): void
    {
        $this->checkOn();
        $this->adminToken();

        $created = $this->api('POST', '/api/v1/users', ['email' => self::EMAIL, 'password' => self::BREACHED]);
        self::assertSame(422, $created->getStatusCode());
        self::assertNull($this->account());

        $created = $this->api('POST', '/api/v1/users', ['email' => self::EMAIL, 'password' => self::GOOD]);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        $id = self::document($created)['id'];
        self::assertIsString($id);

        $patched = $this->api('PATCH', '/api/v1/users/' . $id, ['password' => self::BREACHED]);
        self::assertSame(422, $patched->getStatusCode());
        // The refusal does not repeat the value at fault.
        self::assertStringNotContainsString(self::BREACHED, (string) $patched->getBody());
    }

    private function checkOn(): void
    {
        $this->boot(['CLAVIA_BREACHED_PASSWORD_CHECK' => 'true']);
        $this->install();
    }

    /** The fake service, reached at a public address the policy accepts. */
    private function install(): void
    {
        $this->container()->setService(ClientInterface::class, $this->service);
        $this->container()->setService(
            OutboundUrlPolicy::class,
            new OutboundUrlPolicy(false, static fn (): array => ['104.16.0.1']),
        );
    }

    private function openSignUp(): void
    {
        $connections = $this->container()->get(ConnectionRepository::class);
        $pool = $connections->find(ConnectionName::defaultPool());
        self::assertNotNull($pool);
        $connections->save($pool->switched(null, null, null, true, false));
    }

    private function signUp(string $password): ResponseInterface
    {
        return $this->post('/auth/signup', [
            'email' => self::EMAIL,
            'password' => $password,
            'csrf_token' => self::csrfTokenFrom($this->get('/auth/login')),
            'state' => '',
        ]);
    }

    private function account(): ?User
    {
        return $this->container()->get(UserRepository::class)->findByEmail(ConnectionName::defaultPool(), self::EMAIL);
    }

    /** The reset link of the last message, as the browser would request it. */
    private function resetLink(): string
    {
        $mail = $this->container()->get(MailOutbox::class)->recent(1)[0] ?? null;
        self::assertNotNull($mail, 'Nothing was sent.');
        self::assertSame(
            1,
            preg_match('#https://[^/\s]+(/auth/password/reset\?token=[A-Za-z0-9_-]+)#', $mail->text, $match),
        );

        return $match[1];
    }

    private static function tokenOf(string $link): string
    {
        parse_str((string) parse_url($link, PHP_URL_QUERY), $query);
        $token = $query['token'] ?? null;
        self::assertIsString($token);

        return $token;
    }
}
