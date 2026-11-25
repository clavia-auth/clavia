<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection\Saml;

use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;

/**
 * A signing certificate an identity provider published, kept as PEM: it is pinned, so only its key
 * matters (docs/design/saml-connections.md §2, "Which keys verify"). Its fingerprint and its expiry
 * are shown to operators, read-only; the expiry is never enforced, since identity providers ship
 * self-signed certificates whose dates mean nothing.
 */
final readonly class SamlCertificate
{
    /**
     * @param non-empty-string $pem
     * @param non-empty-string $fingerprint
     */
    private function __construct(
        public string $pem,
        public string $fingerprint,
        public ?DateTimeImmutable $notAfter,
    ) {
    }

    /**
     * @param ?DateTimeImmutable $notAfter What the certificate says, as read when it was checked.
     *
     * @throws InvalidValue When it is not one PEM certificate.
     */
    public static function fromPem(string $pem, ?DateTimeImmutable $notAfter): self
    {
        $form = '/^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+\/=\n]+)-----END CERTIFICATE-----\n?$/D';
        if (preg_match($form, $pem, $match) !== 1) {
            throw new InvalidValue('A SAML signing certificate is one PEM certificate.');
        }
        $der = base64_decode(str_replace("\n", '', $match[1]), true);
        if ($der === false || $der === '' || $pem === '') {
            throw new InvalidValue('A SAML signing certificate is one PEM certificate.');
        }

        return new self($pem, hash('sha256', $der), $notAfter);
    }
}
