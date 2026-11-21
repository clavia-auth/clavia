<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Remote\Gcp;

use Clavia\Adapter\Secondary\Signing\Remote\AccessTokens;
use Clavia\Adapter\Secondary\Signing\Remote\IssuedToken;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Shared\Clock;
use Closure;
use Google\Auth\FetchAuthTokenInterface;
use Throwable;

/**
 * Tokens for Cloud KMS from Google's application default credentials — the metadata
 * server on Google Cloud, workload identity federation, or the key file
 * `GOOGLE_APPLICATION_CREDENTIALS` names — resolved by `google/auth`, which this backend
 * requires.
 */
final class GoogleCredentials implements AccessTokens
{
    /** The narrowest scope Cloud KMS accepts. */
    public const string SCOPE = 'https://www.googleapis.com/auth/cloudkms';

    private const string SERVICE = 'Google Cloud authentication';

    private ?FetchAuthTokenInterface $credentials = null;

    private ?IssuedToken $current = null;

    /**
     * @param Closure(): FetchAuthTokenInterface $resolve The credentials, resolved at the first
     *                                                   token rather than at boot: finding none
     *                                                   must not stop the server starting.
     */
    public function __construct(
        private readonly Closure $resolve,
        private readonly Clock $clock,
    ) {
    }

    #[\Override]
    public function token(): string
    {
        $now = $this->clock->now();
        if ($this->current?->isUsableAt($now) !== true) {
            try {
                /** @var array<array-key, mixed> $response */
                $response = ($this->credentials ??= ($this->resolve)())->fetchAuthToken();
            } catch (Throwable $failed) {
                throw new SigningFailed(
                    sprintf('%s failed: %s', self::SERVICE, $failed->getMessage()),
                    previous: $failed,
                );
            }
            $this->current = IssuedToken::fromResponse($response, $now, self::SERVICE);
        }

        return $this->current->token;
    }
}
