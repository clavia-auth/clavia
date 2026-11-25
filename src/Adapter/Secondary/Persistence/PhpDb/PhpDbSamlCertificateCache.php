<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Adapter\Secondary\Saml\Remote\CachedCertificate;
use Clavia\Adapter\Secondary\Saml\Remote\CertificateCache;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;

/**
 * Remote SAML key certificates in `saml_remote_certificates`. The first writer wins: two processes
 * building the same key's certificate at once keep one, and either is as good.
 */
final readonly class PhpDbSamlCertificateCache implements CertificateCache
{
    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function get(string $reference): ?CachedCertificate
    {
        /**
         * @var array{kid: non-empty-string, usage: string, certificate: non-empty-string, valid_until: string,
         *     created_at: string}|null $row
         */
        $row = $this->database->fetchOne(
            'SELECT kid, usage, certificate, valid_until, created_at FROM saml_remote_certificates '
            . 'WHERE reference = :reference',
            ['reference' => $reference],
        );

        return $row === null ? null : new CachedCertificate(
            $row['kid'],
            ServiceProviderKeyUsage::from($row['usage']),
            $row['certificate'],
            Timestamp::fromDatabase($row['valid_until']),
            Timestamp::fromDatabase($row['created_at']),
        );
    }

    #[\Override]
    public function put(string $reference, CachedCertificate $certificate): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO saml_remote_certificates (reference, kid, usage, certificate, valid_until, created_at)
                VALUES (:reference, :kid, :usage, :certificate, :valid_until, :created_at)
                ON CONFLICT (reference) DO NOTHING
                SQL,
            [
                'reference' => $reference,
                'kid' => $certificate->kid,
                'usage' => $certificate->usage->value,
                'certificate' => $certificate->certificate,
                'valid_until' => Timestamp::toDatabase($certificate->validUntil),
                'created_at' => Timestamp::toDatabase($certificate->createdAt),
            ],
        );
    }
}
