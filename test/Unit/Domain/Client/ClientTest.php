<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Client;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClientTest extends TestCase
{
    public function testAPublicClientHasNoSecret(): void
    {
        $client = $this->register();

        self::assertTrue($client->isPublic());
        self::assertNull($client->secretHash());
        self::assertSame(ClientAuthMethod::None, $client->authMethod);
    }

    public function testAConfidentialClientKeepsTheHashOfItsSecret(): void
    {
        $client = $this->register(
            type: ClientType::Confidential,
            authMethod: ClientAuthMethod::ClientSecretPost,
            secretHash: '$hash$',
        );

        self::assertFalse($client->isPublic());
        self::assertSame('$hash$', $client->secretHash());
    }

    /**
     * RFC 6749 §2.1: the type is whether the client can keep a secret, so the type, the
     * secret and the authentication method have to tell the same story.
     */
    #[DataProvider('contradictions')]
    public function testARegistrationThatContradictsItselfIsRefused(
        ClientType $type,
        ClientAuthMethod $authMethod,
        ?string $secretHash,
    ): void {
        $this->expectException(InvalidValue::class);

        $this->register(type: $type, authMethod: $authMethod, secretHash: $secretHash);
    }

    /** @return iterable<string, array{ClientType, ClientAuthMethod, string|null}> */
    public static function contradictions(): iterable
    {
        yield 'public with a secret' => [ClientType::Public, ClientAuthMethod::None, '$hash$'];
        yield 'public authenticating with a secret' => [ClientType::Public, ClientAuthMethod::ClientSecretBasic, null];
        yield 'confidential without a secret' => [ClientType::Confidential, ClientAuthMethod::ClientSecretBasic, null];
        yield 'confidential with an empty one' => [ClientType::Confidential, ClientAuthMethod::ClientSecretBasic, ''];
        yield 'confidential not authenticating' => [ClientType::Confidential, ClientAuthMethod::None, '$hash$'];
    }

    public function testARedirectUriWithAFragmentIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        $this->register(redirectUris: [Url::fromString('https://app.example/cb#frag')]);
    }

    public function testAClientThatMayAskForACodeNeedsSomewhereToReceiveIt(): void
    {
        $this->expectException(InvalidValue::class);

        $this->register(redirectUris: []);
    }

    public function testAClientThatAsksForNoCodeNeedsNoRedirectUri(): void
    {
        $client = $this->register(redirectUris: [], responseTypes: []);

        self::assertSame([], $client->redirectUris);
        self::assertNull($client->soleRedirectUri());
    }

    public function testANameLongerThan120BytesIsRefused(): void
    {
        self::assertSame(str_repeat('n', 120), $this->register(name: str_repeat('n', 120))->name);

        $this->expectException(InvalidValue::class);

        $this->register(name: str_repeat('n', 121));
    }

    public function testARedirectUriMatchesOnlyExactly(): void
    {
        $client = $this->register(redirectUris: [Url::fromString('https://app.example/cb')]);

        self::assertTrue($client->hasRedirectUri('https://app.example/cb'));
    }

    /**
     * No prefix, wildcard or normalisation matching: each of these is a classic route to
     * an open redirect, and with it to a stolen authorization code (OAuth 2.1 §2.3.1).
     */
    #[DataProvider('lookalikes')]
    public function testALookalikeRedirectUriDoesNotMatch(string $candidate): void
    {
        $client = $this->register(redirectUris: [Url::fromString('https://app.example/cb')]);

        self::assertFalse($client->hasRedirectUri($candidate));
    }

    /** @return iterable<string, array{string}> */
    public static function lookalikes(): iterable
    {
        yield 'a longer path' => ['https://app.example/cb/extra'];
        yield 'a trailing slash' => ['https://app.example/cb/'];
        yield 'a query added' => ['https://app.example/cb?next=https://evil.example'];
        yield 'a fragment added' => ['https://app.example/cb#x'];
        yield 'another scheme' => ['http://app.example/cb'];
        yield 'an explicit default port' => ['https://app.example:443/cb'];
        yield 'another case' => ['https://APP.example/cb'];
        yield 'a subdomain' => ['https://evil.app.example/cb'];
        yield 'a suffix domain' => ['https://app.example.evil.example/cb'];
        yield 'userinfo' => ['https://app.example@evil.example/cb'];
        yield 'a dot segment' => ['https://app.example/x/../cb'];
        yield 'percent-encoded' => ['https://app.example/%63b'];
        yield 'a prefix' => ['https://app.example/c'];
        yield 'empty' => [''];
    }

    public function testTheSoleRedirectUriIsOnlyThereWhenThereIsExactlyOne(): void
    {
        $one = $this->register(redirectUris: [Url::fromString('https://app.example/cb')]);
        $two = $this->register(redirectUris: [
            Url::fromString('https://app.example/cb'),
            Url::fromString('https://app.example/other'),
        ]);

        self::assertSame('https://app.example/cb', $one->soleRedirectUri()?->value);
        self::assertNull($two->soleRedirectUri());
    }

    public function testGrantsAndResponseTypesAreOptIn(): void
    {
        $registered = $this->register();
        $bare = $this->register(redirectUris: [], grantTypes: [], responseTypes: []);

        self::assertTrue($registered->mayUseGrant(GrantType::AuthorizationCode));
        self::assertTrue($registered->mayUseResponseType(ResponseType::Code));
        self::assertFalse($bare->mayUseGrant(GrantType::AuthorizationCode));
        self::assertFalse($bare->mayUseResponseType(ResponseType::Code));
    }

    public function testDuplicatesAreDroppedFromTheLists(): void
    {
        $client = $this->register(
            grantTypes: [GrantType::AuthorizationCode, GrantType::AuthorizationCode],
            responseTypes: [ResponseType::Code, ResponseType::Code],
        );

        self::assertSame([GrantType::AuthorizationCode], $client->grantTypes);
        self::assertSame([ResponseType::Code], $client->responseTypes);
    }

    /**
     * @param list<Url>|null     $redirectUris
     * @param list<GrantType>    $grantTypes
     * @param list<ResponseType> $responseTypes
     */
    private function register(
        string $name = 'App',
        ClientType $type = ClientType::Public,
        ClientAuthMethod $authMethod = ClientAuthMethod::None,
        ?string $secretHash = null,
        ?array $redirectUris = null,
        array $grantTypes = [GrantType::AuthorizationCode],
        array $responseTypes = [ResponseType::Code],
    ): Client {
        return Client::register(
            ClientId::fromString('app'),
            $name,
            $type,
            $authMethod,
            $secretHash,
            $redirectUris ?? [Url::fromString('https://app.example/cb')],
            $grantTypes,
            $responseTypes,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }
}
