<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\E2e\Context;

use Behat\Behat\Context\Context;
use Behat\Step\Then;
use Behat\Step\When;
use Fig\Http\Message\RequestMethodInterface;

/**
 * Plain requests to either host, and what came back: the context of the scenarios about the edge, where
 * Caddy decides before the application is asked.
 */
final class HttpContext implements Context
{
    private Browser $browser;

    /** The stylesheet the last page named, as it named it. */
    private string $stylesheet = '';

    public function __construct()
    {
        $this->browser = new Browser(Stack::fromEnvironment());
    }

    public function browser(): Browser
    {
        return $this->browser;
    }

    #[When('I request :path on the :host host')]
    public function iRequest(string $path, string $host): void
    {
        $this->browser->request(RequestMethodInterface::METHOD_GET, 'https://' . $host . '.' . Stack::DOMAIN . $path);
    }

    #[Then('the status is :status')]
    public function theStatusIs(int $status): void
    {
        Check::same($status, $this->browser->last()->getStatusCode(), $this->browser->last()->getReasonPhrase());
    }

    #[Then('I am sent to :path on the :host host')]
    public function iAmSentTo(string $path, string $host): void
    {
        Check::contains($this->browser->last()->getStatusCode(), [301, 302, 303, 307, 308]);
        $location = $this->browser->location();
        Check::same('https://' . $host . '.' . Stack::DOMAIN . $path, $location);
    }

    #[When('a client posts a token request without a grant type')]
    public function aTokenRequestWithoutAGrantType(): void
    {
        // Refused before any client is authenticated, so it counts against no failure limit.
        $this->browser->request(
            RequestMethodInterface::METHOD_POST,
            $this->browser->stack()->authUrl('/oauth2/token'),
            ['form_params' => ['client_id' => 'nobody']],
        );
    }

    #[When('I request the stylesheet the page names')]
    public function iRequestTheStylesheetThePageNames(): void
    {
        $html = (string) $this->browser->last()->getBody();
        Check::same(1, preg_match('/<link rel="stylesheet" href="([^"]+)">/', $html, $link), 'no stylesheet');
        $this->stylesheet = html_entity_decode($link[1], ENT_QUOTES | ENT_HTML5);
        Check::startsWith('/auth/static/', $this->stylesheet);
        $stylesheet = $this->browser->stack()->authUrl($this->stylesheet);
        $this->browser->request(RequestMethodInterface::METHOD_GET, $stylesheet);
    }

    #[Then('the answer is not cacheable')]
    public function theAnswerIsNotCacheable(): void
    {
        Check::includes('no-store', $this->browser->last()->getHeaderLine('Cache-Control'));
    }

    #[Then('it is served over HTTPS only, for a year')]
    public function itIsServedOverHttpsOnly(): void
    {
        Check::startsWith('max-age=31536000', $this->browser->last()->getHeaderLine('Strict-Transport-Security'));
    }

    #[Then('it cannot be framed')]
    public function itCannotBeFramed(): void
    {
        Check::same('DENY', $this->browser->last()->getHeaderLine('X-Frame-Options'));
        Check::includes("frame-ancestors 'none'", $this->browser->last()->getHeaderLine('Content-Security-Policy'));
    }

    #[Then('its policy allows no inline script and nothing from another origin')]
    public function itsPolicyIsClosed(): void
    {
        $policy = $this->browser->last()->getHeaderLine('Content-Security-Policy');
        Check::startsWith("default-src 'none'", $policy);
        Check::same(0, preg_match('/unsafe-|https?:|\*/', $policy), 'the policy opens up: ' . $policy);
    }

    #[Then('it is CSS, revalidated on every use')]
    public function itIsCss(): void
    {
        Check::startsWith('text/css', $this->browser->last()->getHeaderLine('Content-Type'));
        Check::same('no-cache', $this->browser->last()->getHeaderLine('Cache-Control'));
    }

    #[Then('its content is what its address names')]
    public function itsContentIsWhatItsAddressNames(): void
    {
        Check::same(1, preg_match('/\?v=([0-9a-f]{12})$/', $this->stylesheet, $version), 'not versioned');
        Check::same($version[1], substr(hash('sha256', (string) $this->browser->last()->getBody()), 0, 12));
    }

    #[Then('the internal listener answers nobody outside the network')]
    public function theInternalListenerIsNotPublished(): void
    {
        // Probes and metrics are on 8081 inside the network, and published on no address the stack is reached by.
        $socket = @stream_socket_client('tcp://' . $this->browser->stack()->address . ':8081', $code, $message, 2);
        if ($socket !== false) {
            fclose($socket);
        }
        Check::same(false, $socket, 'something listens on port 8081');
    }
}
