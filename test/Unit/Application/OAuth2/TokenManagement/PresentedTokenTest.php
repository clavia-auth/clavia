<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\OAuth2\TokenManagement;

use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Application\OAuth2\TokenManagement\IssuedTokens;
use Clavia\Application\OAuth2\TokenManagement\PresentedToken;
use Clavia\Application\OAuth2\TokenManagement\TokenTypeHint;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\ErrorCode;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\InMemoryAccessTokenRepository;
use ClaviaTest\Support\Fake\InMemoryRefreshTokenRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Reading the token a client asks about or gives back, and finding it.
 */
final class PresentedTokenTest extends TestCase
{
    public function testTheTokenAndItsHintAreRead(): void
    {
        $presented = PresentedToken::from(RequestParameters::fromMap([
            'token' => 'the-token',
            'token_type_hint' => 'refresh_token',
        ]));

        self::assertSame('the-token', $presented->value);
        self::assertSame(TokenTypeHint::RefreshToken, $presented->hint);
        self::assertNull(PresentedToken::from(RequestParameters::fromMap(['token' => 'x']))->hint);
    }

    /**
     * @param array<string, list<string>> $parameters Every value of each parameter.
     */
    #[DataProvider('malformed')]
    public function testAMalformedRequestIsRefused(array $parameters, ErrorCode $error): void
    {
        try {
            PresentedToken::from(new RequestParameters($parameters));
            self::fail('A malformed request was read.');
        } catch (OAuth2Error $refused) {
            self::assertSame($error, $refused->error);
        }
    }

    /** @return iterable<string, array{array<string, list<string>>, ErrorCode}> */
    public static function malformed(): iterable
    {
        yield 'no token' => [[], ErrorCode::InvalidRequest];
        yield 'an empty token' => [['token' => ['']], ErrorCode::InvalidRequest];
        yield 'a repeated token' => [['token' => ['a', 'b']], ErrorCode::InvalidRequest];
        yield 'a repeated hint' => [
            ['token' => ['x'], 'token_type_hint' => ['access_token', 'access_token']],
            ErrorCode::InvalidRequest,
        ];
        foreach (['id_token', 'code', 'Access_Token'] as $hint) {
            yield "the hint '{$hint}'" => [
                ['token' => ['x'], 'token_type_hint' => [$hint]],
                ErrorCode::UnsupportedTokenType,
            ];
        }
    }

    public function testTheHintSaysWhereToLookFirstNotWhereToLookOnly(): void
    {
        $accessTokens = new InMemoryAccessTokenRepository();
        $token = AccessToken::issueToClient(
            AccessTokenId::generate(new SeededRandomSource(1)),
            Digest::of('the-token'),
            ClientId::fromString('machine'),
            Audience::fromString('https://api.example/'),
            ScopeSet::fromString('read'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            3600,
        );
        $accessTokens->add($token);
        $tokens = new IssuedTokens($accessTokens, new InMemoryRefreshTokenRepository());

        foreach ([null, 'access_token', 'refresh_token'] as $hint) {
            $found = $tokens->find(PresentedToken::from(RequestParameters::fromMap(
                $hint === null ? ['token' => 'the-token'] : ['token' => 'the-token', 'token_type_hint' => $hint],
            )));
            self::assertSame($token, $found);
        }
        self::assertNull($tokens->find(PresentedToken::from(RequestParameters::fromMap(['token' => 'another']))));
    }
}
