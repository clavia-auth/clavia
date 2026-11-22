<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Authentication\Passkey\Aaguid;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\CosePublicKey;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Transport;

/**
 * What a verified registration response gives {@see \Clavia\Domain\Authentication\Passkey\Passkey::register()}:
 * the new credential, and the flags its authenticator reported.
 */
final readonly class VerifiedRegistration
{
    /**
     * @param list<Transport> $transports   How the authenticator can be reached, as the browser said.
     * @param bool            $userVerified Whether the authenticator verified the person (the UV flag).
     */
    public function __construct(
        public CredentialId $credentialId,
        public CosePublicKey $publicKey,
        public CoseAlgorithm $algorithm,
        public int $signCount,
        public array $transports,
        public ?Aaguid $aaguid,
        public bool $backupEligible,
        public bool $backedUp,
        public bool $userVerified,
    ) {
    }
}
