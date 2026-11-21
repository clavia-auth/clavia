<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Consent;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\ScopeSet;

/**
 * An authorization request put on hold while the person decides on the consent screen.
 *
 * Kept server-side behind an opaque handle, like a pending sign-in: the browser carries
 * the handle, and nothing about the request — the application, its redirect URI, its
 * `state` — travels through the consent page's URL or form.
 */
final readonly class PendingConsent
{
    /** Long enough to read the screen, short enough that an abandoned one does not linger. */
    public const int LIFETIME_SECONDS = 600;

    /**
     * @param string                $resumeAt         A local path: the authorization request to send the
     *                                                browser back to once the person allows it, without the
     *                                                `consent` it may have prompted for.
     * @param string                $redirectUri      The client's redirect URI, validated against its
     *                                                registration before the request was put on hold: where
     *                                                a refusal goes.
     * @param string|null           $state            The client's `state`, echoed with a refusal.
     * @param UserId                $userId           Who was asked. Nobody else may answer.
     * @param ResourceServerId|null $resourceServerId The API the request named, if any.
     */
    public function __construct(
        public string $resumeAt,
        public string $redirectUri,
        public ?string $state,
        public UserId $userId,
        public ClientId $clientId,
        public ScopeSet $scope,
        public ?ResourceServerId $resourceServerId,
    ) {
    }
}
