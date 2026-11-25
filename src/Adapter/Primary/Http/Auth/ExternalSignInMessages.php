<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

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

    public static function notAvailable(string $provider): string
    {
        return sprintf('Sign-in with %s is not available for this application.', $provider);
    }

    public static function for(ExternalSignInRefused $refused): string
    {
        $provider = $refused->providerLabel;

        return match ($refused->reason) {
            ExternalSignInFailure::Cancelled => sprintf('Sign-in with %s was cancelled or failed.', $provider),
            ExternalSignInFailure::StartedInAnotherBrowser => 'That sign-in did not start in this browser. '
                . 'Please try again.',
            ExternalSignInFailure::Expired => 'That sign-in link has expired. Please try again.',
            ExternalSignInFailure::ProviderFailed => sprintf('Could not complete sign-in with %s.', $provider),
            ExternalSignInFailure::NoVerifiedEmail => sprintf(
                'Your %s account has no verified email address, so it cannot be used to sign in here.',
                $provider,
            ),
            ExternalSignInFailure::AddressAlreadyUsed => 'An account with this email address already exists. '
                . 'Sign in with your password to continue.',
            ExternalSignInFailure::AccountDisabled => 'This account is disabled.',
            ExternalSignInFailure::NotAvailable, ExternalSignInFailure::NotProvisioned => self::notAvailable($provider),
        };
    }
}
