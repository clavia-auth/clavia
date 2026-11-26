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
use Behat\Step\Given;
use Behat\Step\Then;
use Behat\Step\When;
use Fig\Http\Message\RequestMethodInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A confidential machine client, the one `seed-dev` made: its token for the Management API, introspected
 * (RFC 7662) and revoked (RFC 7009) by the client itself, and what a client address that keeps presenting
 * a wrong secret is told (`invalid_client`, then `429` with `Retry-After`, before any secret is checked).
 */
final class MachineContext implements Context
{
    private readonly Browser $browser;
    private string $clientId = '';
    private string $secret = '';
    private string $token = '';
    /** @var list<ResponseInterface> */
    private array $refusals = [];
    private int $retryAfter = 0;

    public function __construct()
    {
        $this->browser = new Browser(Stack::fromEnvironment());
    }

    #[Given('the machine client of the stack')]
    public function theMachineClientOfTheStack(): void
    {
        // `id:secret`, which Stack::machineCredentials() has already held to that shape.
        $credentials = explode(':', $this->browser->stack()->machineCredentials(), 2);
        $this->clientId = $credentials[0];
        $this->secret = $credentials[1] ?? '';
    }

    #[When('it asks for a token for the Management API')]
    public function itAsksForAToken(): void
    {
        $response = $this->tokenRequest($this->secret);
        Check::same(200, $response->getStatusCode(), (string) $response->getBody());
        $token = self::json($response)['access_token'] ?? null;
        Check::string($token, 'an access token');
        $this->token = $token;
    }

    #[Then('introspecting the token says it is active and was issued to the client')]
    public function introspectingSaysActive(): void
    {
        $answer = $this->introspect();
        Check::same(true, $answer['active'] ?? null, 'active');
        Check::same($this->clientId, $answer['client_id'] ?? null);
        Check::same($this->browser->stack()->managementAudience(), $answer['aud'] ?? null);
    }

    #[Then('the Management API accepts it')]
    public function theManagementApiAcceptsIt(): void
    {
        Check::same(200, $this->managementApi()->getStatusCode(), (string) $this->browser->last()->getBody());
    }

    #[When('the client revokes the token')]
    public function theClientRevokesTheToken(): void
    {
        $response = $this->browser->request(
            RequestMethodInterface::METHOD_POST,
            $this->browser->stack()->authUrl('/oauth2/revoke'),
            ['headers' => $this->basic($this->secret), 'form_params' => ['token' => $this->token]],
        );
        Check::same(200, $response->getStatusCode(), (string) $response->getBody());
    }

    #[Then('introspecting the token says it is no longer active')]
    public function introspectingSaysInactive(): void
    {
        // RFC 7662 §2.2: a token that is not active is described by that alone.
        Check::same(['active' => false], $this->introspect());
    }

    #[Then('the Management API refuses it')]
    public function theManagementApiRefusesIt(): void
    {
        $response = $this->managementApi();
        Check::same(401, $response->getStatusCode());
        Check::includes('invalid_token', $response->getHeaderLine('WWW-Authenticate'));
    }

    #[When('it presents a wrong secret :times times')]
    public function itPresentsAWrongSecret(int $times): void
    {
        // Failures are counted per address and every scenario shares this one: let the window of any
        // earlier failure (CLAVIA_TOKEN_FAILURE_WINDOW, five seconds here) pass first.
        sleep(6);
        for ($attempt = 0; $attempt < $times; ++$attempt) {
            $this->refusals[] = $this->tokenRequest('not-' . $this->secret);
        }
    }

    #[Then('each was refused as an invalid client, with a challenge')]
    public function eachWasRefusedAsAnInvalidClient(): void
    {
        Check::that($this->refusals !== [], 'no attempt was made');
        foreach ($this->refusals as $refusal) {
            Check::same(401, $refusal->getStatusCode(), (string) $refusal->getBody());
            Check::startsWith('Basic', $refusal->getHeaderLine('WWW-Authenticate'));
            Check::same('invalid_client', self::json($refusal)['error'] ?? null);
        }
    }

    #[Then('even its right secret is then refused for now, with a time to wait')]
    public function evenItsRightSecretIsRefused(): void
    {
        $response = $this->tokenRequest($this->secret);
        Check::same(429, $response->getStatusCode(), (string) $response->getBody());
        Check::same('temporarily_unavailable', self::json($response)['error'] ?? null);
        Check::matches('/^[1-9][0-9]*$/D', $response->getHeaderLine('Retry-After'), 'a Retry-After in seconds');
        $this->retryAfter = (int) $response->getHeaderLine('Retry-After');
    }

    #[Then('once that time has passed, its right secret is accepted again')]
    public function onceThatTimeHasPassed(): void
    {
        sleep($this->retryAfter + 1);
        $response = $this->tokenRequest($this->secret);
        Check::same(200, $response->getStatusCode(), (string) $response->getBody());
    }

    private function tokenRequest(string $secret): ResponseInterface
    {
        $stack = $this->browser->stack();

        return $this->browser->request(RequestMethodInterface::METHOD_POST, $stack->authUrl('/oauth2/token'), [
            'headers' => $this->basic($secret),
            'form_params' => ['grant_type' => 'client_credentials', 'audience' => $stack->managementAudience()],
        ]);
    }

    /** @return array<string, mixed> */
    private function introspect(): array
    {
        $response = $this->browser->request(
            RequestMethodInterface::METHOD_POST,
            $this->browser->stack()->authUrl('/oauth2/introspect'),
            ['headers' => $this->basic($this->secret), 'form_params' => ['token' => $this->token]],
        );
        Check::same(200, $response->getStatusCode(), (string) $response->getBody());
        Check::includes('no-store', $response->getHeaderLine('Cache-Control'));

        return self::json($response);
    }

    private function managementApi(): ResponseInterface
    {
        return $this->browser->request(
            RequestMethodInterface::METHOD_GET,
            $this->browser->stack()->managementUrl('/api/v1/clients?per_page=1'),
            ['headers' => ['Authorization' => 'Bearer ' . $this->token]],
        );
    }

    /** @return array{Authorization: string} */
    private function basic(string $secret): array
    {
        return ['Authorization' => 'Basic ' . base64_encode($this->clientId . ':' . $secret)];
    }

    /** @return array<string, mixed> */
    private static function json(ResponseInterface $response): array
    {
        /** @var array<string, mixed> */
        return json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
    }
}
