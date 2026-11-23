<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Clients;

use Clavia\Application\Clients\Registration\RegistrationErrorCode;
use Clavia\Application\Clients\Registration\RegistrationMetadata;
use Clavia\Application\Clients\Registration\RegistrationRefused;
use Clavia\Application\Management\Clients\BackChannelLogoutRegistration;
use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Shared\Url;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The metadata policy of self-registration (RFC 7591 §2; docs/design/
 * dynamic-client-registration.md §2), without a request.
 */
final class RegistrationMetadataTest extends TestCase
{
    private const array APP = ['client_name' => 'Acme', 'redirect_uris' => ['https://acme.example/cb']];

    public function testTheDefaultsAreAConfidentialClientOfTheCodeFlow(): void
    {
        $metadata = self::policy()->read(self::APP);

        // RFC 7591 §2: client_secret_basic, authorization_code and code when nothing is said.
        self::assertSame(ClientAuthMethod::ClientSecretBasic, $metadata->authMethod);
        self::assertSame(ClientType::Confidential, $metadata->type);
        self::assertSame([GrantType::AuthorizationCode], $metadata->grantTypes);
        self::assertSame([ResponseType::Code], $metadata->responseTypes);
        self::assertSame([], $metadata->postLogoutRedirectUris);
        self::assertNull($metadata->backChannelLogout);
        self::assertFalse($metadata->requireDpop);
    }

    public function testNoAuthenticationIsAPublicClientWhichMayUseLoopback(): void
    {
        $metadata = self::policy()->read([
            'client_name' => 'Acme CLI',
            'token_endpoint_auth_method' => 'none',
            'grant_types' => ['authorization_code', 'refresh_token', 'refresh_token'],
            'redirect_uris' => ['http://127.0.0.1:8400/cb'],
            'dpop_bound_access_tokens' => true,
        ]);

        self::assertSame(ClientType::Public, $metadata->type);
        self::assertSame([GrantType::AuthorizationCode, GrantType::RefreshToken], $metadata->grantTypes, 'Once each.');
        $uris = array_map(static fn (Url $uri): string => $uri->value, $metadata->redirectUris);
        self::assertSame(['http://127.0.0.1:8400/cb'], $uris);
        self::assertTrue($metadata->requireDpop);
    }

    public function testWhatIsTheOperatorsOrUnknownIsIgnored(): void
    {
        $metadata = self::policy()->read(self::APP + [
            'require_pkce' => false,
            'mfa_policy' => 'required',
            'require_pushed_authorization_requests' => true,
            'connections' => ['Username-Password-Authentication'],
            'is_first_party' => true,
            'scope' => 'openid admin',
            'logo_uri' => 'https://acme.example/logo.png',
        ]);

        self::assertSame('Acme', $metadata->name);
        self::assertSame(ClientType::Confidential, $metadata->type);
    }

    public function testABackChannelLogoutUriIsKeptWhenThisServerMayPostToIt(): void
    {
        $metadata = self::policy()->read(self::APP + [
            'backchannel_logout_uri' => 'https://acme.example/logout',
            'backchannel_logout_session_required' => true,
        ]);

        self::assertNotNull($metadata->backChannelLogout);
        self::assertSame('https://acme.example/logout', $metadata->backChannelLogout->uri->value);
        self::assertTrue($metadata->backChannelLogout->sessionRequired);
    }

    /**
     * @param array<string, mixed> $members
     */
    #[DataProvider('refusals')]
    public function testWhatASelfRegisteredClientMayNotHaveIsRefused(array $members, RegistrationErrorCode $error): void
    {
        try {
            self::policy()->read($members);
            self::fail('The metadata was accepted.');
        } catch (RegistrationRefused $refusal) {
            self::assertSame($error, $refusal->error);
        }
    }

    /** @return iterable<string, array{array<string, mixed>, RegistrationErrorCode}> */
    public static function refusals(): iterable
    {
        $metadata = RegistrationErrorCode::InvalidClientMetadata;
        $redirect = RegistrationErrorCode::InvalidRedirectUri;
        yield 'no name' => [['redirect_uris' => self::APP['redirect_uris']], $metadata];
        yield 'an empty name' => [['client_name' => ''] + self::APP, $metadata];
        yield 'client credentials' => [['grant_types' => ['client_credentials']] + self::APP, $metadata];
        yield 'the device flow' => [
            ['grant_types' => ['urn:ietf:params:oauth:grant-type:device_code']] + self::APP,
            $metadata,
        ];
        yield 'an unknown grant' => [['grant_types' => ['password']] + self::APP, $metadata];
        yield 'a token response' => [['response_types' => ['code', 'token']] + self::APP, $metadata];
        yield 'the code grant without code' => [['response_types' => []] + self::APP, $metadata];
        yield 'a refresh token alone' => [
            ['grant_types' => ['refresh_token'], 'response_types' => []] + self::APP,
            $metadata,
        ];
        yield 'private_key_jwt' => [['token_endpoint_auth_method' => 'private_key_jwt'] + self::APP, $metadata];
        yield 'a boolean as a string' => [['dpop_bound_access_tokens' => 'yes'] + self::APP, $metadata];
        yield 'an object for a list' => [
            ['client_name' => 'x', 'redirect_uris' => ['a' => 'https://acme.example/cb']],
            $metadata,
        ];
        yield 'a back-channel URI at home' => [
            ['backchannel_logout_uri' => 'https://127.0.0.1/logout'] + self::APP,
            $metadata,
        ];
        yield 'a software statement' => [
            ['software_statement' => 'x'] + self::APP,
            RegistrationErrorCode::InvalidSoftwareStatement,
        ];
        yield 'no redirect URI' => [['client_name' => 'x'], $redirect];
        yield 'a relative URI' => [['client_name' => 'x', 'redirect_uris' => ['/cb']], $redirect];
        yield 'http on a host' => [['client_name' => 'x', 'redirect_uris' => ['http://acme.example/cb']], $redirect];
        yield 'loopback for a confidential client' => [
            ['client_name' => 'x', 'redirect_uris' => ['http://[::1]/cb']],
            $redirect,
        ];
        yield 'localhost' => [[
            'client_name' => 'x',
            'token_endpoint_auth_method' => 'none',
            'redirect_uris' => ['http://localhost/cb'],
        ], $redirect];
        yield 'a fragment' => [['client_name' => 'x', 'redirect_uris' => ['https://acme.example/cb#here']], $redirect];
    }

    private static function policy(): RegistrationMetadata
    {
        // Every name resolves to a public address: only literals and reserved names are refused.
        return new RegistrationMetadata(new BackChannelLogoutRegistration(
            new OutboundUrlPolicy(false, static fn (): array => ['93.184.216.34']),
        ));
    }
}
