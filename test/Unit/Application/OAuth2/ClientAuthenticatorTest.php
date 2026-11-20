<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\OAuth2;

use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\ClientAuthentication\ClientCredentials;
use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\OAuth2\ErrorCode;
use Clavia\Domain\OAuth2\OAuth2Error;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClientAuthenticatorTest extends TestCase
{
    private const array ALL = [
        ClientAuthMethod::ClientSecretBasic,
        ClientAuthMethod::ClientSecretPost,
        ClientAuthMethod::None,
    ];

    private ClientAuthenticator $authenticator;

    #[\Override]
    protected function setUp(): void
    {
        $hasher = new FakePasswordHasher();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public('spa'));
        $clients->save(Clients::confidential('basic-app', $hasher->hash('s3cret:with colon')));
        $clients->save(Clients::confidential('post-app', $hasher->hash('s3cret'), ClientAuthMethod::ClientSecretPost));
        $clients->save(Clients::confidential('odd+id/100%', $hasher->hash('p@ss word&more')));

        $this->authenticator = new ClientAuthenticator($clients, $hasher);
    }

    public function testAPublicClientIdentifiesItselfWithItsIdAlone(): void
    {
        $client = $this->authenticate(body: ['client_id' => 'spa']);

        self::assertSame('spa', $client->id->value);
    }

    public function testAConfidentialClientAuthenticatesWithHttpBasic(): void
    {
        $client = $this->authenticate(header: $this->basic('basic-app', 's3cret:with colon'));

        self::assertSame('basic-app', $client->id->value);
    }

    public function testBasicCredentialsAreFormEncodedBeforeBeingJoined(): void
    {
        // RFC 6749 §2.3.1: id and secret are each form-urlencoded, then joined with ":".
        $header = 'Basic ' . base64_encode(urlencode('odd+id/100%') . ':' . urlencode('p@ss word&more'));

        self::assertSame('odd+id/100%', $this->authenticate(header: $header)->id->value);
    }

    public function testTheBasicSchemeIsCaseInsensitive(): void
    {
        $header = 'bAsIc ' . base64_encode('basic-app:' . urlencode('s3cret:with colon'));

        self::assertSame('basic-app', $this->authenticate(header: $header)->id->value);
    }

    public function testAConfidentialClientRegisteredForItAuthenticatesInTheBody(): void
    {
        $client = $this->authenticate(body: ['client_id' => 'post-app', 'client_secret' => 's3cret']);

        self::assertSame('post-app', $client->id->value);
    }

    /**
     * @param array<string, string> $body
     */
    #[DataProvider('failures')]
    public function testAnythingElseIsOneAndTheSameFailure(?string $header, array $body): void
    {
        try {
            $this->authenticate($header, $body);
            self::fail('The client was authenticated.');
        } catch (OAuth2Error $error) {
            self::assertSame(ErrorCode::InvalidClient, $error->error);
            self::assertSame('Client authentication failed.', $error->description);
        }
    }

    /** @return iterable<string, array{string|null, array<string, string>}> */
    public static function failures(): iterable
    {
        $basic = static fn (string $id, string $secret): string
            => 'Basic ' . base64_encode(urlencode($id) . ':' . urlencode($secret));

        yield 'nothing at all' => [null, []];
        yield 'an unknown public client' => [null, ['client_id' => 'nobody']];
        yield 'a malformed client id' => [null, ['client_id' => 'not an id']];
        yield 'a wrong secret over Basic' => [$basic('basic-app', 'wrong'), []];
        yield 'an empty secret over Basic' => ['Basic ' . base64_encode('basic-app:'), []];
        yield 'an unknown client over Basic' => [$basic('nobody', 's3cret'), []];
        yield 'a wrong secret in the body' => [null, ['client_id' => 'post-app', 'client_secret' => 'wrong']];
        // One registered method per client: the right secret through the wrong door is refused.
        yield 'a Basic client using the body' => [
            null,
            ['client_id' => 'basic-app', 'client_secret' => 's3cret:with colon'],
        ];
        yield 'a body client using Basic' => [$basic('post-app', 's3cret'), []];
        // The downgrade a secret exists to prevent.
        yield 'a confidential client presenting only its id' => [null, ['client_id' => 'basic-app']];
        yield 'a public client presenting a secret' => [null, ['client_id' => 'spa', 'client_secret' => 'anything']];
        yield 'a public client over Basic' => [$basic('spa', ''), []];
        yield 'a Bearer header' => ['Bearer abc', []];
        yield 'Basic that is not base64' => ['Basic !!!not-base64!!!', []];
        yield 'Basic without a colon' => ['Basic ' . base64_encode('basic-app'), []];
        yield 'Basic with nothing after it' => ['Basic ', []];
    }

    public function testAMethodTheCallerDoesNotAcceptIsNotTried(): void
    {
        $this->expectException(OAuth2Error::class);

        $this->authenticator->authenticate(
            new ClientCredentials(null, RequestParameters::fromMap(['client_id' => 'spa'])),
            [ClientAuthMethod::ClientSecretBasic, ClientAuthMethod::ClientSecretPost],
        );
    }

    public function testFailedBasicCredentialsDoNotFallBackToAnIdInTheBody(): void
    {
        // Wrong Basic credentials plus a public client's id in the body: the body names a
        // public client that did authenticate with "none", so that is who the caller is.
        // What must not happen is the Basic client being let in.
        $client = $this->authenticate($this->basic('basic-app', 'wrong'), ['client_id' => 'spa']);

        self::assertSame('spa', $client->id->value);
    }

    /**
     * @param array<string, string> $body
     */
    private function authenticate(?string $header = null, array $body = []): Client
    {
        return $this->authenticator->authenticate(
            new ClientCredentials($header, RequestParameters::fromMap($body)),
            self::ALL,
        );
    }

    private function basic(string $clientId, string $secret): string
    {
        return 'Basic ' . base64_encode(urlencode($clientId) . ':' . urlencode($secret));
    }
}
