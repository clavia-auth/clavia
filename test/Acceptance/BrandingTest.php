<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Client\AccentColor;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientLogo;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestImages;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Branding per application (#25): a logo, a name and an accent colour on the sign-in pages of a request
 * for that application, set through the Management API, served from the sign-in origin, with the pages'
 * policy as it was: no inline style, no image from anywhere else.
 */
final class BrandingTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->publicClient();
        $this->adminToken();
    }

    public function testAnAccentColourIsSetAndServedAsAStylesheet(): void
    {
        $updated = $this->patch(['accent_color' => '#0F766E']);

        self::assertSame(StatusCodeInterface::STATUS_OK, $updated->getStatusCode(), (string) $updated->getBody());
        self::assertSame('#0f766e', self::document($updated)['accent_color']);
        $style = $this->get('/auth/branding/' . self::TEST_CLIENT_ID . '/style.css');
        self::assertSame(StatusCodeInterface::STATUS_OK, $style->getStatusCode());
        self::assertSame('text/css; charset=utf-8', $style->getHeaderLine('Content-Type'));
        self::assertSame('nosniff', $style->getHeaderLine('X-Content-Type-Options'));
        self::assertSame(
            ":root {\n  --accent: #0f766e;\n  --accent-hover: color-mix(in srgb, #0f766e 85%, #000);\n"
            . "  --accent-text: #ffffff;\n}\n",
            (string) $style->getBody(),
        );
    }

    public function testAPaleColourCarriesDarkText(): void
    {
        $this->patch(['accent_color' => '#f9e27d']);

        $style = (string) $this->get('/auth/branding/' . self::TEST_CLIENT_ID . '/style.css')->getBody();

        self::assertStringContainsString('--accent-text: #12211a;', $style);
    }

    public function testTheSignInPagesWearTheApplicationsLook(): void
    {
        $this->patch(['accent_color' => '#0f766e', 'name' => 'Acme <Reports>']);
        $this->putLogo(TestImages::png(96, 48));
        $version = self::document($this->client())['logo_version'];
        self::assertIsString($version);

        $page = $this->loginPage();

        $body = (string) $page->getBody();
        $base = '&#x2F;auth&#x2F;branding&#x2F;' . self::TEST_CLIENT_ID;
        self::assertStringContainsString(
            '<link rel="stylesheet" href="' . $base . '&#x2F;style.css&#x3F;v&#x3D;0f766e">',
            $body,
        );
        self::assertStringContainsString(
            '<img class="brand-logo" src="' . $base . '&#x2F;logo&#x3F;v&#x3D;' . $version . '" alt="">',
            $body,
        );
        self::assertStringContainsString('<p class="brand-name">Acme &lt;Reports&gt;</p>', $body);
        self::assertStringNotContainsString('class="brand-mark"', $body);
        // The policy is the one every page has: no inline style, images from this origin only.
        $policy = $page->getHeaderLine('Content-Security-Policy');
        self::assertStringContainsString("img-src 'self'", $policy);
        self::assertStringNotContainsString('unsafe-inline', $policy);
        self::assertStringNotContainsString(' style=', $body);
    }

    /** The consent screen wears it for the person asked; ConsentTest shows anyone else gets "expired". */
    public function testTheConsentScreenWearsItForThePersonAsked(): void
    {
        $this->loggedIn();
        $this->container()->get(ClientRepository::class)->save(Client::register(
            ClientId::fromString('tpc_partner'),
            'Partner Analytics',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString(self::TEST_REDIRECT_URI)],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            $this->container()->get(Clock::class)->now(),
        )->withAccentColor(AccentColor::fromString('#7c3aed')));

        $asked = $this->get(
            '/oauth2/authorize',
            $this->authorizeParams($this->makePkcePair()[1], ['client_id' => 'tpc_partner']),
        );
        self::assertStringStartsWith('/auth/consent?state=', $asked->getHeaderLine('Location'));
        $screen = (string) $this->request(
            RequestMethodInterface::METHOD_GET,
            $asked->getHeaderLine('Location'),
            ['Accept' => 'text/html'],
        )->getBody();

        self::assertStringContainsString('<p class="brand-name">Partner Analytics</p>', $screen);
        self::assertStringContainsString('style.css&#x3F;v&#x3D;7c3aed', $screen);
    }

    public function testAPageForNoApplicationKeepsThisServersLook(): void
    {
        $this->patch(['accent_color' => '#0f766e']);

        $body = (string) $this->request(RequestMethodInterface::METHOD_GET, '/auth/login', ['Accept' => 'text/html'])
            ->getBody();

        self::assertStringContainsString('class="brand-mark"', $body);
        self::assertStringNotContainsString('brand-name', $body);
        self::assertStringNotContainsString('/auth/branding/', html_entity_decode($body));
    }

    public function testTheLogoIsServedAsTheImageItIs(): void
    {
        $png = TestImages::png();
        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $this->putLogo($png)->getStatusCode());

        $public = $this->get('/auth/branding/' . self::TEST_CLIENT_ID . '/logo');
        self::assertSame(StatusCodeInterface::STATUS_OK, $public->getStatusCode());
        self::assertSame('image/png', $public->getHeaderLine('Content-Type'));
        self::assertSame($png, (string) $public->getBody());
        self::assertSame('nosniff', $public->getHeaderLine('X-Content-Type-Options'));
        self::assertSame("default-src 'none'; sandbox", $public->getHeaderLine('Content-Security-Policy'));
        $managed = $this->api(
            RequestMethodInterface::METHOD_GET,
            '/api/v1/clients/' . self::TEST_CLIENT_ID . '/logo',
        );
        self::assertSame($png, (string) $managed->getBody());
    }

    public function testWhatIsNotAnImageWithinTheBoundsIsRefused(): void
    {
        $refusals = [
            'an SVG' => TestImages::svg(),
            'text' => 'not an image at all',
            'too small' => TestImages::png(8, 8),
            'too wide' => TestImages::png(2048, 16),
            'too heavy' => TestImages::png() . str_repeat("\0", ClientLogo::MAX_BYTES),
        ];
        foreach ($refusals as $what => $bytes) {
            self::assertSame(
                StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
                $this->putLogo($bytes)->getStatusCode(),
                $what,
            );
        }
        self::assertNull(self::document($this->client())['logo_version']);
        self::assertSame(
            StatusCodeInterface::STATUS_UNSUPPORTED_MEDIA_TYPE,
            $this->putLogo(TestImages::svg(), 'image/svg+xml')->getStatusCode(),
        );
    }

    public function testABadColourIsRefused(): void
    {
        foreach (['0f766e', '#0f766', 'red', '#0f766e;}', '#GGGGGG'] as $color) {
            self::assertSame(
                StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
                $this->patch(['accent_color' => $color])->getStatusCode(),
                $color,
            );
        }
    }

    public function testRemovingTheBrandingGivesThePagesBackTheirOwn(): void
    {
        $this->patch(['accent_color' => '#0f766e']);
        $this->putLogo(TestImages::png());

        $this->patch(['accent_color' => null]);
        $removed = $this->removeLogo();

        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $removed->getStatusCode());
        $client = self::document($this->client());
        self::assertNull($client['accent_color']);
        self::assertNull($client['logo_version']);
        foreach (['logo', 'style.css'] as $file) {
            $gone = $this->get('/auth/branding/' . self::TEST_CLIENT_ID . '/' . $file);
            self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $gone->getStatusCode(), $file);
        }
        self::assertStringContainsString('class="brand-mark"', (string) $this->loginPage()->getBody());
        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->removeLogo()->getStatusCode(),
            'Nothing left to remove.',
        );
    }

    public function testAnUnknownApplicationHasNoBranding(): void
    {
        $paths = ['/auth/branding/nobody/logo', '/auth/branding/nobody/style.css', '/auth/branding/%3A/logo'];
        foreach ($paths as $path) {
            self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->get($path)->getStatusCode(), $path);
        }
    }

    public function testEachChangeIsAuditedByItsFieldNeverItsValue(): void
    {
        $this->patch(['accent_color' => '#0f766e']);
        $this->putLogo(TestImages::png());
        $this->removeLogo();

        $details = array_column(TestStorage::database()->fetchAll(
            'SELECT details::text AS details FROM audit_events WHERE type = :type ORDER BY occurred_at, id',
            ['type' => AuditEventType::ClientUpdated->value],
        ), 'details');

        self::assertCount(3, $details);
        self::assertStringContainsString('"accent_color"', (string) $details[0]);
        self::assertStringNotContainsString('0f766e', (string) $details[0]);
        self::assertStringContainsString('"logo"', (string) $details[1]);
        self::assertStringContainsString('"removed": true', (string) $details[2]);
    }

    /** @param array<string, mixed> $changes */
    private function patch(array $changes): ResponseInterface
    {
        return $this->api(RequestMethodInterface::METHOD_PATCH, '/api/v1/clients/' . self::TEST_CLIENT_ID, $changes);
    }

    private function putLogo(string $bytes, string $type = 'image/png'): ResponseInterface
    {
        return $this->api(
            RequestMethodInterface::METHOD_PUT,
            '/api/v1/clients/' . self::TEST_CLIENT_ID . '/logo',
            headers: ['Content-Type' => $type],
            rawBody: $bytes,
        );
    }

    private function removeLogo(): ResponseInterface
    {
        return $this->api(RequestMethodInterface::METHOD_DELETE, '/api/v1/clients/' . self::TEST_CLIENT_ID . '/logo');
    }

    private function client(): ResponseInterface
    {
        return $this->api(RequestMethodInterface::METHOD_GET, '/api/v1/clients/' . self::TEST_CLIENT_ID);
    }

    /** The login page an authorization request for the application sends the browser to. */
    private function loginPage(): ResponseInterface
    {
        $asked = $this->get('/oauth2/authorize', $this->authorizeParams($this->makePkcePair()[1]));
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $asked->getStatusCode(), (string) $asked->getBody());

        return $this->request(
            RequestMethodInterface::METHOD_GET,
            $asked->getHeaderLine('Location'),
            ['Accept' => 'text/html'],
        );
    }
}
