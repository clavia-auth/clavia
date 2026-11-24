<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\HtmlPage;
use Clavia\Application\Authentication\Mfa\EnrolmentOnTheWay;
use Clavia\Application\Authentication\Passkey\AccountPasskeys;
use Clavia\Application\Authentication\Passkey\AssertionOptions;
use Clavia\Application\Authentication\Passkey\DescribedPasskey;
use Clavia\Application\Authentication\Passkey\RegistrationOptions;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\Transport;
use Clavia\Domain\Shared\Base64Url;
use Fig\Http\Message\StatusCodeInterface;

/**
 * The view models of the passkey pages: the account's passkeys, and the page that makes one.
 *
 * The page that makes one is the only page of this origin that runs script, `passkeys.js`, and
 * the options it hands the browser travel as JSON in an escaped `data-` attribute of its form —
 * data the page carries, never script it runs.
 */
final class PasskeyPages
{
    public const string PATH = '/auth/passkeys';

    public const string SCRIPT = '/auth/static/passkeys.js';

    public const string START_AGAIN = 'That did not work. Try adding the passkey again.';

    public const string ALREADY_REGISTERED = 'That passkey is already registered.';

    public const string INVALID_NAME = 'A passkey needs a name of one to 64 characters.';

    public const string NOT_FOUND = 'That passkey is not on this account any more.';

    public const string LAST_WAY_IN = 'This passkey is the only way into your account. '
        . 'Choose a password first, then remove it.';

    private function __construct()
    {
    }

    /** The account's passkeys, and the way to add, rename or remove one. */
    public static function list(
        AccountPasskeys $passkeys,
        ?string $error = null,
        int $status = StatusCodeInterface::STATUS_OK,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::passkeys',
            title: 'Passkeys',
            heading: 'Passkeys',
            returnTo: self::PATH,
            variables: [
                'email' => $passkeys->email,
                'passkeys' => array_map(self::row(...), $passkeys->passkeys),
                'canAddAnother' => $passkeys->canAddAnother(),
                'limit' => $passkeys->limit,
            ],
            error: $error,
            status: $status,
        );
    }

    /** The page where the browser makes the passkey, from the options of an open ceremony. */
    public static function create(
        RegistrationOptions $options,
        ?string $error = null,
        int $status = StatusCodeInterface::STATUS_OK,
        ?EnrolmentOnTheWay $onTheWay = null,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::passkey-new',
            title: 'Add a passkey',
            heading: 'Add a passkey',
            variables: [
                'email' => $options->userName,
                'options' => json_encode(self::creationOptions($options), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
                // On the way to an application requiring a second factor: carried back to it.
                'loginState' => $onTheWay->loginState ?? '',
            ],
            // Making the passkey may lead straight back to the application's redirect URI.
            formOrigins: $onTheWay === null ? [] : $onTheWay->formOrigins,
            error: $error,
            status: $status,
            script: self::SCRIPT,
        );
    }

    /**
     * The recovery codes that came with the account's first passkey, shown this once — and, on
     * the way to an application, the way back to it.
     *
     * @param list<string> $codes
     */
    public static function recoveryCodes(array $codes, ?EnrolmentOnTheWay $onTheWay = null): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::passkey-codes',
            title: 'Recovery codes',
            heading: 'Your passkey is ready',
            variables: ['codes' => $codes, 'loginState' => $onTheWay->loginState ?? ''],
            wide: true,
            formOrigins: $onTheWay === null ? [] : $onTheWay->formOrigins,
        );
    }

    /**
     * `PublicKeyCredentialCreationOptionsJSON` (WebAuthn Level 3 §5.4, §5.1.9): every binary value
     * in base64url, which `PublicKeyCredential.parseCreationOptionsFromJSON()` reads as it is.
     *
     * @return array<string, mixed>
     */
    public static function creationOptions(RegistrationOptions $options): array
    {
        $user = $options->challenge->userId;
        assert($user !== null);

        return [
            'rp' => ['id' => $options->relyingParty->id, 'name' => $options->relyingParty->name],
            'user' => [
                'id' => Base64Url::encode($user->toBytes()),
                'name' => $options->userName,
                'displayName' => $options->displayName,
            ],
            'challenge' => $options->challenge->toBase64Url(),
            'pubKeyCredParams' => array_map(
                static fn (CoseAlgorithm $algorithm): array => ['type' => 'public-key', 'alg' => $algorithm->value],
                $options->algorithms(),
            ),
            'timeout' => $options->timeoutSeconds * 1000,
            'excludeCredentials' => array_map(
                static fn (Passkey $passkey): array => [
                    'type' => 'public-key',
                    'id' => $passkey->credentialId->toBase64Url(),
                    'transports' => array_map(static fn (Transport $t): string => $t->value, $passkey->transports),
                ],
                $options->exclude,
            ),
            'authenticatorSelection' => [
                'residentKey' => 'required',
                'requireResidentKey' => true,
                'userVerification' => 'required',
            ],
            'attestation' => 'none',
            'hints' => ['client-device', 'hybrid'],
        ];
    }

    /**
     * `PublicKeyCredentialRequestOptionsJSON` (WebAuthn Level 3 §5.5, §5.1.9), which
     * `PublicKeyCredential.parseRequestOptionsFromJSON()` reads as it is.
     *
     * @return array<string, mixed>
     */
    public static function requestOptions(AssertionOptions $options): array
    {
        return [
            'challenge' => $options->challenge->toBase64Url(),
            'rpId' => $options->relyingParty->id,
            'timeout' => $options->timeoutSeconds * 1000,
            'allowCredentials' => array_map(
                static fn (Passkey $passkey): array => [
                    'type' => 'public-key',
                    'id' => $passkey->credentialId->toBase64Url(),
                    'transports' => array_map(static fn (Transport $t): string => $t->value, $passkey->transports),
                ],
                $options->allow,
            ),
            'userVerification' => $options->requiresUserVerification() ? 'required' : 'preferred',
            'hints' => ['client-device', 'security-key', 'hybrid'],
        ];
    }

    /**
     * @return array{id: string, name: string, synced: bool, createdAt: string, lastUsedAt: string|null}
     */
    private static function row(DescribedPasskey $passkey): array
    {
        return [
            'id' => $passkey->id,
            'name' => $passkey->name,
            'synced' => $passkey->synced,
            'createdAt' => $passkey->createdAt->format('j M Y'),
            'lastUsedAt' => $passkey->lastUsedAt?->format('j M Y'),
        ];
    }
}
