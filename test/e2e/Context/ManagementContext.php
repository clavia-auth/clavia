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
use Behat\Step\When;
use Fig\Http\Message\RequestMethodInterface;

/**
 * People and applications, made through the Management API with the machine client `seed-dev` printed,
 * each under a name no other scenario uses: the stack is shared by the whole run and never wiped.
 */
final class ManagementContext implements Context
{
    private ?string $token = null;
    private ?Person $person = null;
    private ?Application $application = null;
    private ?string $pool = null;
    private readonly Browser $api;

    public function __construct()
    {
        $this->api = new Browser(Stack::fromEnvironment());
    }

    public function person(): Person
    {
        return $this->person ?? throw new \LogicException('No person: add a Given step.');
    }

    public function application(): Application
    {
        return $this->application ?? throw new \LogicException('No application: add a Given step.');
    }

    #[Given('a person who signs in with a password')]
    public function aPersonWhoSignsInWithAPassword(): void
    {
        $email = 'e2e-' . bin2hex(random_bytes(6)) . '@clavia.test';
        $password = 'pw-' . bin2hex(random_bytes(12));
        $created = $this->call(RequestMethodInterface::METHOD_POST, '/api/v1/users', [
            'email' => $email,
            'password' => $password,
            'email_verified' => true,
            'name' => 'End To End',
        ]);
        $this->person = new Person((string) $created['id'], $email, $password);
    }

    #[Given('an application that allows signing in and refreshing, redirecting to :redirectUri')]
    public function anApplicationThatAllowsSigningInAndRefreshing(string $redirectUri): void
    {
        $this->application = $this->createApplication($redirectUri, ['password']);
    }

    #[Given('an application on a device without a browser')]
    public function anApplicationOnADevice(): void
    {
        $created = $this->call(RequestMethodInterface::METHOD_POST, '/api/v1/clients', [
            'name' => 'End to end device ' . bin2hex(random_bytes(4)),
            'client_type' => 'public',
            'token_endpoint_auth_method' => 'none',
            'grant_types' => ['urn:ietf:params:oauth:grant-type:device_code'],
            'response_types' => [],
            'is_first_party' => true,
            'connections' => ['password'],
        ]);
        $this->application = new Application((string) $created['client_id'], '');
    }

    #[Given('a pool that takes sign-ups and requires a verified address')]
    public function aPoolThatTakesSignUps(): void
    {
        $name = 'e2e-' . bin2hex(random_bytes(6));
        $this->call(RequestMethodInterface::METHOD_POST, '/api/v1/connections', [
            'name' => $name,
            'display_name' => 'End to end ' . $name,
            'strategy' => 'database',
            'is_enabled' => true,
            'is_domain_connection' => false,
            'allow_sign_up' => true,
            'require_verified_email' => true,
        ]);
        $this->pool = $name;
    }

    #[Given('an application whose people come from that pool, redirecting to :redirectUri')]
    public function anApplicationWhosePeopleComeFromThatPool(string $redirectUri): void
    {
        $pool = $this->pool ?? throw new \LogicException('No pool: add a Given step.');
        $this->application = $this->createApplication($redirectUri, [$pool]);
    }

    #[Given('a visitor with a new address and password')]
    public function aVisitorWithANewAddress(): void
    {
        $email = 'e2e-' . bin2hex(random_bytes(6)) . '@clavia.test';
        $this->person = new Person('', $email, 'pw-' . bin2hex(random_bytes(12)));
    }

    #[Given('a person who was created without a password')]
    public function aPersonCreatedWithoutAPassword(): void
    {
        $email = 'e2e-' . bin2hex(random_bytes(6)) . '@clavia.test';
        $created = $this->call(RequestMethodInterface::METHOD_POST, '/api/v1/users', ['email' => $email]);
        $this->person = new Person((string) $created['id'], $email, '');
    }

    #[When('an operator sends the person a password link')]
    public function anOperatorSendsThePersonAPasswordLink(): void
    {
        $this->call(
            RequestMethodInterface::METHOD_POST,
            '/api/v1/users/' . $this->person()->id . '/password-reset',
            null,
            202,
        );
    }

    /**
     * @param list<string> $connections
     */
    private function createApplication(string $redirectUri, array $connections): Application
    {
        $created = $this->call(RequestMethodInterface::METHOD_POST, '/api/v1/clients', [
            'name' => 'End to end ' . bin2hex(random_bytes(4)),
            'client_type' => 'public',
            'token_endpoint_auth_method' => 'none',
            'redirect_uris' => [$redirectUri],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'is_first_party' => true,
            'connections' => $connections,
        ]);

        return new Application((string) $created['client_id'], $redirectUri);
    }

    /**
     * @param array<string, mixed>|null $body
     * @return array<string, mixed>
     */
    private function call(string $method, string $path, ?array $body, int $expected = 201): array
    {
        $response = $this->api->request($method, $this->api->stack()->managementUrl($path), [
            'headers' => ['Authorization' => 'Bearer ' . $this->token()],
        ] + ($body === null ? [] : ['json' => $body]));
        Check::same(
            $expected,
            $response->getStatusCode(),
            sprintf('%s %s: %s', $method, $path, (string) $response->getBody()),
        );

        /** @var array<string, mixed> */
        return json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
    }

    private function token(): string
    {
        if ($this->token !== null) {
            return $this->token;
        }
        $stack = $this->api->stack();
        $response = $this->api->request(RequestMethodInterface::METHOD_POST, $stack->authUrl('/oauth2/token'), [
            'headers' => ['Authorization' => 'Basic ' . base64_encode($stack->machineCredentials())],
            'form_params' => ['grant_type' => 'client_credentials', 'audience' => $stack->managementAudience()],
        ]);
        Check::same(200, $response->getStatusCode(), (string) $response->getBody());
        /** @var array{access_token: string} $token */
        $token = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);

        return $this->token = $token['access_token'];
    }
}
