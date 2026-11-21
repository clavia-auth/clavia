<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\IdentityProvider;
use Clavia\Application\Port\IdentityProviderFailed;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\Oidc\Nonce;

/**
 * An external provider that says whatever the test tells it to, and remembers how it
 * was asked.
 */
final class FakeIdentityProvider implements IdentityProvider
{
    public const string AUTHORIZATION_ENDPOINT = 'https://idp.example/authorize';

    public ?string $subject = 'subject-1';

    public ?string $email = 'ada@example.com';

    public bool $emailVerified = true;

    public bool $fails = false;

    /** @var list<array{code: string, redirectUri: string, verifier: string, nonce: string}> */
    public array $exchanges = [];

    public function __construct(private readonly string $name = 'google')
    {
    }

    #[\Override]
    public function name(): ConnectionName
    {
        return ConnectionName::fromString($this->name);
    }

    #[\Override]
    public function authorizationUrl(
        string $redirectUri,
        string $state,
        CodeChallenge $challenge,
        Nonce $nonce,
    ): string {
        return self::AUTHORIZATION_ENDPOINT . '?' . http_build_query([
            'redirect_uri' => $redirectUri,
            'state' => $state,
            'code_challenge' => $challenge->value,
            'nonce' => $nonce->value,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    #[\Override]
    public function identify(
        #[\SensitiveParameter] string $code,
        string $redirectUri,
        CodeVerifier $verifier,
        Nonce $nonce,
    ): AssertedIdentity {
        $this->exchanges[] = [
            'code' => $code,
            'redirectUri' => $redirectUri,
            'verifier' => $verifier->value,
            'nonce' => $nonce->value,
        ];
        if ($this->fails || $this->subject === null) {
            throw new IdentityProviderFailed('The fake provider was told to fail.');
        }

        return AssertedIdentity::of($this->name(), $this->subject, $this->email, $this->emailVerified);
    }
}
