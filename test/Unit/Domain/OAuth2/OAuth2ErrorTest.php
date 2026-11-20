<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\OAuth2;

use Clavia\Domain\OAuth2\ErrorCode;
use Clavia\Domain\OAuth2\OAuth2Error;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class OAuth2ErrorTest extends TestCase
{
    #[DataProvider('errors')]
    public function testEachErrorCarriesItsRegisteredCode(OAuth2Error $error, ErrorCode $code, string $wire): void
    {
        self::assertSame($code, $error->error);
        self::assertSame($wire, $error->error->value);
        self::assertSame('why', $error->description);
        self::assertSame($wire . ': why', $error->getMessage());
    }

    /** @return iterable<string, array{OAuth2Error, ErrorCode, string}> */
    public static function errors(): iterable
    {
        yield 'invalid_request' => [OAuth2Error::invalidRequest('why'), ErrorCode::InvalidRequest, 'invalid_request'];
        yield 'invalid_client' => [OAuth2Error::invalidClient('why'), ErrorCode::InvalidClient, 'invalid_client'];
        yield 'invalid_grant' => [OAuth2Error::invalidGrant('why'), ErrorCode::InvalidGrant, 'invalid_grant'];
        yield 'unauthorized_client' => [
            OAuth2Error::unauthorizedClient('why'),
            ErrorCode::UnauthorizedClient,
            'unauthorized_client',
        ];
        yield 'unsupported_grant_type' => [
            OAuth2Error::unsupportedGrantType('why'),
            ErrorCode::UnsupportedGrantType,
            'unsupported_grant_type',
        ];
        yield 'unsupported_response_type' => [
            OAuth2Error::unsupportedResponseType('why'),
            ErrorCode::UnsupportedResponseType,
            'unsupported_response_type',
        ];
        yield 'invalid_scope' => [OAuth2Error::invalidScope('why'), ErrorCode::InvalidScope, 'invalid_scope'];
    }
}
