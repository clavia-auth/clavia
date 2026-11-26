<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Http\Auth\MfaPages;
use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\MfaFactorType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\UserRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\Saml\TestIdentityProvider as Idp;
use ClaviaTest\Support\TestStorage;
use DOMDocument;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Signing in through a SAML identity provider, end to end through the real routes (#126,
 * docs/design/saml-connections.md §5.3): out by HTTP-Redirect, back by the identity provider's POST,
 * parked and turned into a GET where the browser's cookies come back, every check, then the first
 * factor. Plain assertions and unsigned requests, from {@see Idp}.
 */
final class SamlSignInTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;
    use LoginFixtures;

    private const string SESSION_COOKIE = 'clavia_session';
    private const string STATE_COOKIE = 'clavia_external_state';

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->freezeClock(Idp::NOW);
        $this->adminToken();
    }

    public function testAPersonSignsInAndAnAccountIsMadeForTheirSubject(): void
    {
        $this->registerSaml(['email_attribute' => 'email', 'email_trusted' => true]);

        [$requestId, $relayState] = $this->start();
        $finished = $this->finish(self::answering($requestId), $relayState);

        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $finished->getStatusCode(),
            (string) $finished->getBody(),
        );
        $identity = $this->container()->get(ExternalIdentityRepository::class)
            ->find(ConnectionName::fromString('acme'), 'a8f3c2d1-0b9e-4f7a-8c6d-5e4f3a2b1c0d');
        self::assertNotNull($identity, 'Linked by (connection, subject), never the address.');
        $user = $this->container()->get(UserRepository::class)->find($identity->userId);
        self::assertNotNull($user);
        self::assertSame('ada@acme.example', $user->email);
        self::assertTrue($user->isEmailVerified(), 'The operator trusts this identity provider for addresses.');
        $session = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($session);
        self::assertTrue($session->userId->equals($user->id));
        self::assertSame(['ext'], array_map(static fn ($method): string => $method->value, $session->methods));
        self::assertNull($this->cookie(self::STATE_COOKIE), 'The pairing cookie is spent.');
    }

    public function testAnAddressTheOperatorDoesNotTrustStaysUnverifiedAndLinksToNothing(): void
    {
        $this->registerSaml(['email_attribute' => 'email']);
        [$requestId, $relayState] = $this->start();

        $this->finish(self::answering($requestId), $relayState);

        $user = $this->samlUser();
        self::assertNotNull($user);
        self::assertFalse($user->isEmailVerified());
    }

    public function testASecondFactorAppliesAsAfterAnySignIn(): void
    {
        $this->registerSaml(['email_attribute' => 'email', 'email_trusted' => true]);
        [$requestId, $relayState] = $this->start();
        $this->finish(self::answering($requestId), $relayState);
        $user = $this->samlUser();
        self::assertNotNull($user);
        $now = new \DateTimeImmutable(Idp::NOW);
        $this->container()->get(MfaFactorRepository::class)->save(
            MfaFactor::reconstitute($user->id, MfaFactorType::Totp, 'sealed-seed', $now, 0, $now),
        );
        $this->clearCookies();

        [$requestId, $relayState] = $this->start();
        $finished = $this->finish(
            self::answering($requestId, ['assertionId' => '_a2']),
            $relayState,
        );

        self::assertSame(MfaPages::CHALLENGE_PATH, $finished->getHeaderLine('Location'));
        self::assertNull($this->cookie(self::SESSION_COOKIE), 'Not signed in yet.');
    }

    public function testTheLoginPageOffersTheConnection(): void
    {
        $this->registerSaml([]);

        $page = (string) $this->get('/auth/login')->getBody();

        self::assertStringContainsString('href="&#x2F;auth&#x2F;saml&#x2F;acme"', $page, 'Escaped, as every value is.');
        self::assertStringContainsString('Acme staff', $page);
    }

    public function testEveryRefusalIsOnePageAndNothingFromTheIdentityProviderIsShown(): void
    {
        $this->registerSaml([]);
        $cases = [
            'signed by another key' => static fn (string $id): string
                => self::answering($id, ['key' => Idp::attacker()]),
            'for another request' => static fn (string $id): string => Idp::response(),
            'a failed status' => static fn (string $id): string
                => self::answering($id, ['status' => 'urn:oasis:names:tc:SAML:2.0:status:Responder']),
        ];
        $pages = [];
        foreach ($cases as $case => $response) {
            $this->clearCookies();
            [$requestId, $relayState] = $this->start();
            $refused = $this->finish($response($requestId), $relayState);
            self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $refused->getStatusCode(), $case);
            self::assertStringNotContainsString('Responder', (string) $refused->getBody());
            self::assertNull($this->cookie(self::SESSION_COOKIE), $case);
            $pages[] = preg_replace('/name="csrf_token" value="[^"]+"/', '', (string) $refused->getBody());
        }
        self::assertCount(1, array_unique($pages), 'One page, whatever went wrong.');
        self::assertSame(3, (int) TestStorage::database()->fetchValue(
            "SELECT count(*) FROM audit_events WHERE type = 'authentication.failed' "
            . "AND details->>'connection' = 'acme'",
        ));
        self::assertTrue($this->logger->hasRecordContaining('signature'), 'The category is logged.');
    }

    public function testAResponseThatComesBackToAnotherBrowserSignsNobodyIn(): void
    {
        $this->registerSaml([]);
        [$requestId, $relayState] = $this->start();
        $this->clearCookies();

        $refused = $this->finish(self::answering($requestId), $relayState);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $refused->getStatusCode());
        self::assertTrue($this->logger->hasRecordContaining('StartedInAnotherBrowser'));
    }

    public function testAnAssertionIsAcceptedOnce(): void
    {
        $this->registerSaml([]);
        [$requestId, $relayState] = $this->start();
        $this->finish(self::answering($requestId), $relayState);
        $this->clearCookies();

        // The same assertion, signed again for a new request: its id was spent.
        [$requestId, $relayState] = $this->start();
        $replayed = $this->finish(self::answering($requestId), $relayState);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $replayed->getStatusCode());
        self::assertTrue($this->logger->hasRecordContaining('replayed'));
    }

    public function testTheAcsTakesOnlyAResponseAndAParkedOneOnlyOnce(): void
    {
        $this->registerSaml([]);
        $noResponse = $this->post('/auth/saml/acme/acs', ['RelayState' => 'x']);
        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $noResponse->getStatusCode());

        [$requestId, $relayState] = $this->start();
        $acs = $this->post('/auth/saml/acme/acs', [
            'SAMLResponse' => self::answering($requestId),
            'RelayState' => $relayState,
        ]);
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $acs->getStatusCode());
        $complete = $acs->getHeaderLine('Location');
        self::assertStringStartsWith('/auth/saml/acme/complete?h=', $complete);
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->get($complete)->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $this->get($complete)->getStatusCode(), 'Once.');
    }

    public function testASwitchedOffConnectionIsGone(): void
    {
        $this->registerSaml([]);
        $this->api(RequestMethodInterface::METHOD_PATCH, '/api/v1/connections/acme', ['is_enabled' => false]);

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->get('/auth/saml/acme')->getStatusCode());
    }

    private function samlUser(): ?\Clavia\Domain\Identity\User
    {
        return $this->container()->get(UserRepository::class)
            ->findByEmail(ConnectionName::fromString('acme'), 'ada@acme.example');
    }

    /**
     * Begin at this server: the request it sent, and the handle the browser now holds.
     *
     * @return array{0: string, 1: string}
     */
    private function start(): array
    {
        $started = $this->get('/auth/saml/acme');
        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $started->getStatusCode(),
            (string) $started->getBody(),
        );
        $location = $started->getHeaderLine('Location');
        self::assertStringStartsWith('https://idp.acme.example/saml/sso?SAMLRequest=', $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $request = new DOMDocument();
        $deflated = (string) base64_decode((string) ($query['SAMLRequest'] ?? ''), true);
        $xml = (string) gzinflate($deflated);
        self::assertTrue($xml !== '' && $request->loadXML($xml));
        $relayState = (string) ($query['RelayState'] ?? '');
        self::assertSame($relayState, $this->cookie(self::STATE_COOKIE));

        return [(string) $request->documentElement?->getAttribute('ID'), $relayState];
    }

    /** The identity provider's POST, then the GET it is turned into. */
    private function finish(string $response, string $relayState): ResponseInterface
    {
        $acs = $this->post('/auth/saml/acme/acs', ['SAMLResponse' => $response, 'RelayState' => $relayState]);
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $acs->getStatusCode(), (string) $acs->getBody());

        return $this->get($acs->getHeaderLine('Location'));
    }

    /**
     * The test identity provider's response to the request `$requestId`.
     *
     * @param array<string, mixed> $options
     */
    private static function answering(string $requestId, array $options = []): string
    {
        return Idp::response($options + ['inResponseTo' => $requestId, 'confirmationInResponseTo' => $requestId]);
    }

    /** @param array<string, mixed> $options */
    private function registerSaml(array $options): void
    {
        $created = $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/connections', [
            'name' => 'acme',
            'display_name' => 'Acme staff',
            'strategy' => 'saml',
            'is_domain_connection' => true,
            'saml' => (object) ($options + [
                'metadata' => Idp::metadata([Idp::rsa()['certificate']]),
                'email_attribute' => 'email',
            ]),
        ]);
        self::assertSame(StatusCodeInterface::STATUS_CREATED, $created->getStatusCode(), (string) $created->getBody());
    }
}
