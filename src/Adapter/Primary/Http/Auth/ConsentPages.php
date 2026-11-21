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
use Clavia\Application\OAuth2\Consent\ConsentScreen;

/**
 * The view models of the consent screen: the question, and the page for a request that
 * is no longer there to answer.
 */
final class ConsentPages
{
    public const string PATH = '/auth/consent';

    public const string EXPIRED = 'This request has expired. Please start again from the application.';

    private function __construct()
    {
    }

    /**
     * What the application asks for, and the two answers.
     *
     * @param non-empty-string $consentState The handle of the request on hold.
     */
    public static function question(
        ConsentScreen $screen,
        string $consentState,
        ?string $error = null,
        int $status = 200,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::consent',
            title: 'Allow access',
            heading: 'Allow access?',
            returnTo: self::address($consentState),
            variables: [
                'consentState' => $consentState,
                'clientName' => $screen->clientName,
                'email' => $screen->email,
                'oidcScopes' => $screen->oidcScopes,
                'api' => $screen->api,
            ],
            error: $error,
            status: $status,
            // Allow or refuse, the browser ends up at the application.
            formOrigins: $screen->formOrigins,
        );
    }

    /**
     * The handle stands for nothing — unknown, decided, timed out, or not this person's.
     * Shown rather than redirected: without the request there is no destination that can
     * be trusted.
     */
    public static function expired(): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::consent-expired',
            title: 'Request expired',
            heading: 'Request expired',
            returnTo: self::PATH,
            error: self::EXPIRED,
            status: 400,
        );
    }

    /** The screen's own address, rebuilt so a page re-rendered by a failed POST keeps it. */
    private static function address(string $consentState): string
    {
        return self::PATH . '?' . http_build_query(['state' => $consentState], '', '&', PHP_QUERY_RFC3986);
    }
}
