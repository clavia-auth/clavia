<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc\Discovery;

use Clavia\Application\OAuth2\TokenManagement\IntrospectToken;
use Clavia\Application\OAuth2\TokenManagement\RevokeToken;
use Clavia\Domain\Authentication\AuthenticationLevel;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\Prompt;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\ScopeSet;

/**
 * What this server is and does: the OpenID Provider Metadata (OpenID Connect Discovery
 * 1.0 §3), which is also its Authorization Server Metadata (RFC 8414 §2).
 *
 * Relying parties configure themselves from this document, so it is a contract: it
 * names only what the server actually does, and states every field whose
 * specification default says otherwise — a client that assumes `request_uri` support or
 * the implicit grant because a field was left out fails at the worst moment.
 */
final readonly class ProviderMetadata
{
    /*
     * Where each endpoint lives, below the issuer. The routes must agree; an acceptance
     * test fetches every endpoint the document names.
     */
    public const string AUTHORIZATION_ENDPOINT = '/oauth2/authorize';
    public const string TOKEN_ENDPOINT = '/oauth2/token';
    public const string INTROSPECTION_ENDPOINT = '/oauth2/introspect';
    public const string PUSHED_AUTHORIZATION_REQUEST_ENDPOINT = '/oauth2/par';
    public const string REVOCATION_ENDPOINT = '/oauth2/revoke';
    public const string DEVICE_AUTHORIZATION_ENDPOINT = '/oauth2/device/code';
    public const string USERINFO_ENDPOINT = '/oidc/userinfo';
    public const string JWKS_URI = '/oidc/jwks.json';
    public const string END_SESSION_ENDPOINT = '/oidc/logout';

    /** The claims an ID token or the userinfo endpoint can carry. */
    private const array CLAIMS = [
        'iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr', 'at_hash', 'sid',
        'name', 'given_name', 'family_name', 'nickname', 'picture', 'locale', 'updated_at',
        'email', 'email_verified',
    ];

    /**
     * @param non-empty-string       $issuer
     * @param list<GrantType>        $grantTypes        What the token endpoint answers.
     * @param list<ClientAuthMethod> $tokenAuthMethods  How a client may authenticate there.
     * @param list<SigningAlgorithm> $signingAlgorithms What ID tokens are signed with.
     */
    public function __construct(
        private string $issuer,
        private ScopeSet $scopes,
        private array $grantTypes,
        private array $tokenAuthMethods,
        private array $signingAlgorithms,
    ) {
    }

    /**
     * The document, fields in the order the specifications list them.
     *
     * @return array<non-empty-string, string|bool|list<string>>
     */
    public function toArray(): array
    {
        return [
            'issuer' => $this->issuer,
            'authorization_endpoint' => $this->issuer . self::AUTHORIZATION_ENDPOINT,
            'token_endpoint' => $this->issuer . self::TOKEN_ENDPOINT,
            'userinfo_endpoint' => $this->issuer . self::USERINFO_ENDPOINT,
            'jwks_uri' => $this->issuer . self::JWKS_URI,
            // OpenID Connect RP-Initiated Logout 1.0 §2.1.
            'end_session_endpoint' => $this->issuer . self::END_SESSION_ENDPOINT,
            'scopes_supported' => $this->scopes->toList(),
            'response_types_supported' => array_map(
                static fn (ResponseType $type): string => $type->value,
                ResponseType::cases(),
            ),
            // The default is ["query", "fragment"]; the fragment mode serves the implicit flow.
            'response_modes_supported' => ['query'],
            // The default is ["authorization_code", "implicit"]; there is no implicit grant here.
            'grant_types_supported' => array_map(
                static fn (GrantType $type): string => $type->value,
                $this->grantTypes,
            ),
            // The levels an `acr` claim can take (OIDC Discovery §3), weakest first; one factor has none.
            'acr_values_supported' => AuthenticationLevel::supportedAcrValues(),
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => array_map(
                static fn (SigningAlgorithm $algorithm): string => $algorithm->value,
                $this->signingAlgorithms,
            ),
            'token_endpoint_auth_methods_supported' => array_map(
                static fn (ClientAuthMethod $method): string => $method->value,
                $this->tokenAuthMethods,
            ),
            // RFC 8414 §2: introspection (RFC 7662) takes a secret; revocation (RFC 7009) a public
            // client's id too.
            'introspection_endpoint' => $this->issuer . self::INTROSPECTION_ENDPOINT,
            // RFC 9126 §5. Whether a client must use it is its own registration's to say (§6).
            'pushed_authorization_request_endpoint' => $this->issuer . self::PUSHED_AUTHORIZATION_REQUEST_ENDPOINT,
            'require_pushed_authorization_requests' => false,
            'introspection_endpoint_auth_methods_supported' => self::methods(IntrospectToken::AUTH_METHODS),
            'revocation_endpoint' => $this->issuer . self::REVOCATION_ENDPOINT,
            'revocation_endpoint_auth_methods_supported' => self::methods(RevokeToken::AUTH_METHODS),
            // RFC 8628 §4.
            'device_authorization_endpoint' => $this->issuer . self::DEVICE_AUTHORIZATION_ENDPOINT,
            'claim_types_supported' => ['normal'],
            'claims_supported' => self::CLAIMS,
            // OIDC Core §3.1.2.1; Discovery has no default for it, so it is always stated.
            'prompt_values_supported' => Prompt::SUPPORTED,
            'claims_parameter_supported' => false,
            'request_parameter_supported' => false,
            // The default is true. This is OIDC's `request_uri`: a request object fetched from a URL,
            // which this server never does. A pushed request's `request_uri` (RFC 9126) is another
            // thing, advertised by `pushed_authorization_request_endpoint`.
            'request_uri_parameter_supported' => false,
            // RFC 8414 §2: absent would mean "no PKCE". `plain` is not offered.
            'code_challenge_methods_supported' => [CodeChallenge::METHOD],
            // RFC 9207 §3: every authorization response names its issuer.
            'authorization_response_iss_parameter_supported' => true,
            // Back-Channel Logout 1.0 §2.1: logout tokens are sent, and always name the session.
            'backchannel_logout_supported' => true,
            'backchannel_logout_session_supported' => true,
        ];
    }

    /**
     * @param list<ClientAuthMethod> $methods
     *
     * @return list<string>
     */
    private static function methods(array $methods): array
    {
        return array_map(static fn (ClientAuthMethod $method): string => $method->value, $methods);
    }
}
