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
