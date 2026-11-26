<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\Message;
use Clavia\Application\Authentication\External\ExternalSignInFailure;
use Clavia\Application\Authentication\External\ExternalSignInRefused;

/**
 * What the login page says when an external sign-in did not end in a session.
 *
 * Every word is this server's. The provider's `error` and `error_description` are never
 * shown: they arrive in a query string anyone can forge, and reflecting them would make
 * the callback a way to put arbitrary text on the sign-in page.
 */
final class ExternalSignInMessages
{
    private function __construct()
    {
    }

    public static function notAvailable(string $provider): Message
    {
        return Message::of('external.error.not_available', ['provider' => $provider]);
    }

    public static function for(ExternalSignInRefused $refused): Message
    {
        $provider = ['provider' => $refused->providerLabel];

        return match ($refused->reason) {
            ExternalSignInFailure::Cancelled => Message::of('external.error.cancelled', $provider),
            ExternalSignInFailure::StartedInAnotherBrowser => Message::of('external.error.another_browser'),
            ExternalSignInFailure::Expired => Message::of('external.error.expired'),
            ExternalSignInFailure::ProviderFailed => Message::of('external.error.provider_failed', $provider),
            ExternalSignInFailure::NoVerifiedEmail => Message::of('external.error.no_verified_email', $provider),
            ExternalSignInFailure::AddressAlreadyUsed => Message::of('external.error.address_already_used'),
            ExternalSignInFailure::AccountDisabled => Message::of(PasswordlessPages::ACCOUNT_DISABLED),
            ExternalSignInFailure::NotAvailable,
            ExternalSignInFailure::NotProvisioned => self::notAvailable($refused->providerLabel),
        };
    }
}
