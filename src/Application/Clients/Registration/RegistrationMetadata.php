<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

use Clavia\Application\Management\Clients\BackChannelLogoutRegistration;
use Clavia\Domain\Client\BackChannelLogout;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;

/**
 * The metadata policy of self-registration (RFC 7591 §2; docs/design/
 * dynamic-client-registration.md §2): what a client registering itself may ask for, read into
 * {@see ClientMetadata}, or refused with the field at fault.
 *
 * The one place the policy lives, so registration and a later update (RFC 7592) cannot drift.
 * It never decides ownership — a self-registered client is third-party by construction, outside
 * anything a request says — nor anything that is the operator's: `require_pkce`, `mfa_policy`,
 * pushed requests, connections. Those members are ignored like any other this server does not
 * take (§2), and the response leaves them out.
 */
final readonly class RegistrationMetadata
{
    private const int MAX_NAME_LENGTH = 120;

    /**
     * What a self-registered client may hold. No machine client: it has nothing to do without a client
     * grant. No device flow: a third-party one is a phishing kit (`Client::register()` refuses it).
     */
    private const array GRANT_TYPES = [GrantType::AuthorizationCode, GrantType::RefreshToken];

    private const array AUTH_METHODS = [
        ClientAuthMethod::None,
        ClientAuthMethod::ClientSecretBasic,
        ClientAuthMethod::ClientSecretPost,
    ];

    /** Loopback literals (RFC 8252 §7.3). Never `localhost` by name, which can resolve elsewhere (§8.3). */
    private const array LOOPBACK_HOSTS = ['127.0.0.1', '[::1]'];

    public function __construct(private BackChannelLogoutRegistration $backChannel)
    {
    }

    /**
     * @param array<array-key, mixed> $members The request's JSON object, member by member.
     *
     * @throws RegistrationRefused
     */
    public function read(array $members): ClientMetadata
    {
        if (array_key_exists('software_statement', $members)) {
            throw RegistrationRefused::softwareStatement();
        }

        $name = self::string($members, 'client_name');
        if ($name === null || $name === '' || strlen($name) > self::MAX_NAME_LENGTH) {
            throw RegistrationRefused::metadata("'client_name' is required, 1 to 120 bytes.");
        }

        // RFC 7591 §2: client_secret_basic when the client names no method.
        $authMethod = self::oneOf(
            $members,
            'token_endpoint_auth_method',
            self::AUTH_METHODS,
            ClientAuthMethod::tryFrom(...),
        ) ?? ClientAuthMethod::ClientSecretBasic;
        $type = $authMethod === ClientAuthMethod::None ? ClientType::Public : ClientType::Confidential;

        // RFC 7591 §2: authorization_code, and code, when the client names none.
        $grantTypes = self::listOf($members, 'grant_types', self::GRANT_TYPES, GrantType::tryFrom(...))
            ?? [GrantType::AuthorizationCode];
        $codeFlow = in_array(GrantType::AuthorizationCode, $grantTypes, true);
        $responseTypes = self::listOf($members, 'response_types', [ResponseType::Code], ResponseType::tryFrom(...))
            ?? ($codeFlow ? [ResponseType::Code] : []);
        // RFC 7591 §2.1: the code grant and the code response type go together.
        if ($codeFlow !== in_array(ResponseType::Code, $responseTypes, true)) {
            throw RegistrationRefused::metadata(
                "'grant_types' and 'response_types' disagree: 'authorization_code' goes with 'code'.",
            );
        }
        if (in_array(GrantType::RefreshToken, $grantTypes, true) && count($grantTypes) === 1) {
            throw RegistrationRefused::metadata("'refresh_token' needs a grant that starts a session.");
        }

        $redirectUris = self::uris($members, 'redirect_uris', $type);
        if ($codeFlow && $redirectUris === []) {
            throw RegistrationRefused::redirectUri("'redirect_uris' is required for the 'authorization_code' grant.");
        }

        return new ClientMetadata(
            $name,
            $type,
            $authMethod,
            $redirectUris,
            $grantTypes,
            $responseTypes,
            self::uris($members, 'post_logout_redirect_uris', $type),
            $this->backChannelLogout($members),
            self::bool($members, 'dpop_bound_access_tokens') ?? false,
        );
    }

    /**
     * @param array<array-key, mixed> $members
     *
     * @throws RegistrationRefused
     */
    private function backChannelLogout(array $members): ?BackChannelLogout
    {
        $uri = self::string($members, 'backchannel_logout_uri');
        $sessionRequired = self::bool($members, 'backchannel_logout_session_required') ?? false;

        try {
            return $this->backChannel->of($uri, $sessionRequired);
        } catch (InvalidValue) {
            throw RegistrationRefused::metadata(
                "'backchannel_logout_uri' must be an https URL, without a fragment, this server may post to.",
            );
        }
    }

    /**
     * Redirect URIs, and post-logout ones, by OAuth 2.1 §2.3.1: https without a fragment, or —
     * for a public client, a native application — http on a loopback literal (RFC 8252 §7.3).
     *
     * @param array<array-key, mixed> $members
     *
     * @return list<Url>
     *
     * @throws RegistrationRefused
     */
    private static function uris(array $members, string $field, ClientType $type): array
    {
        $values = self::strings($members, $field) ?? [];
        $uris = [];
        foreach ($values as $value) {
            try {
                $uri = Url::fromString($value);
            } catch (InvalidValue) {
                throw RegistrationRefused::redirectUri(sprintf("Each of '%s' must be an absolute URL.", $field));
            }
            $loopback = $uri->scheme() === 'http'
                && $type === ClientType::Public
                && in_array($uri->host(), self::LOOPBACK_HOSTS, true);
            if ($uri->hasFragment() || ($uri->scheme() !== 'https' && ! $loopback)) {
                throw RegistrationRefused::redirectUri(sprintf(
                    "Each of '%s' must be https without a fragment, or, for a public client, "
                    . 'http on 127.0.0.1 or [::1].',
                    $field,
                ));
            }
            $uris[] = $uri;
        }

        return $uris;
    }

    /**
     * @template T of \UnitEnum
     *
     * @param array<array-key, mixed>  $members
     * @param list<T>                  $allowed
     * @param callable(string): (T|null) $from
     *
     * @return T|null
     *
     * @throws RegistrationRefused
     */
    private static function oneOf(array $members, string $field, array $allowed, callable $from): ?\UnitEnum
    {
        $value = self::string($members, $field);
        if ($value === null) {
            return null;
        }
        $case = $from($value);
        if ($case === null || ! in_array($case, $allowed, true)) {
            throw RegistrationRefused::metadata(sprintf("'%s' is not one this server accepts.", $field));
        }

        return $case;
    }

    /**
     * @template T of \UnitEnum
     *
     * @param array<array-key, mixed>  $members
     * @param list<T>                  $allowed
     * @param callable(string): (T|null) $from
     *
     * @return list<T>|null Null when the member is absent: its default applies.
     *
     * @throws RegistrationRefused
     */
    private static function listOf(array $members, string $field, array $allowed, callable $from): ?array
    {
        $values = self::strings($members, $field);
        if ($values === null) {
            return null;
        }
        $cases = [];
        foreach ($values as $value) {
            $case = $from($value);
            if ($case === null || ! in_array($case, $allowed, true)) {
                throw RegistrationRefused::metadata(sprintf("'%s' holds a value this server does not accept.", $field));
            }
            if (! in_array($case, $cases, true)) {
                $cases[] = $case;
            }
        }

        return $cases;
    }

    /**
     * @param array<array-key, mixed> $members
     *
     * @throws RegistrationRefused
     */
    private static function string(array $members, string $field): ?string
    {
        /** @var mixed $value */
        $value = $members[$field] ?? null;

        return $value === null || is_string($value)
            ? $value
            : throw RegistrationRefused::metadata(sprintf("'%s' must be a string.", $field));
    }

    /**
     * @param array<array-key, mixed> $members
     *
     * @throws RegistrationRefused
     */
    private static function bool(array $members, string $field): ?bool
    {
        /** @var mixed $value */
        $value = $members[$field] ?? null;

        return $value === null || is_bool($value)
            ? $value
            : throw RegistrationRefused::metadata(sprintf("'%s' must be true or false.", $field));
    }

    /**
     * @param array<array-key, mixed> $members
     *
     * @return list<string>|null
     *
     * @throws RegistrationRefused
     */
    private static function strings(array $members, string $field): ?array
    {
        /** @var mixed $value */
        $value = $members[$field] ?? null;
        if ($value === null) {
            return null;
        }
        if (! is_array($value) || ! array_is_list($value)) {
            throw RegistrationRefused::metadata(sprintf("'%s' must be an array of strings.", $field));
        }
        $strings = [];
        /** @var mixed $item */
        foreach ($value as $item) {
            if (! is_string($item)) {
                throw RegistrationRefused::metadata(sprintf("'%s' must be an array of strings.", $field));
            }
            $strings[] = $item;
        }

        return $strings;
    }
}
