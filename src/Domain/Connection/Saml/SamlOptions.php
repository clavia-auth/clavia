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

/**
 * How a SAML connection reads the person, and what it asks of the identity provider
 * (docs/design/saml-connections.md §2, §4). Every identity provider names attributes its own way,
 * so the mapping is data. The subject is the persistent `NameID` unless an attribute is named
 * (Entra's `objectidentifier`, ADFS's `objectGUID`); never the address. The address is verified
 * only when the operator says the identity provider verifies it.
 */
final readonly class SamlOptions
{
    public const string PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    private const string ATTRIBUTE = '/^[\x21-\x7E]{1,255}$/D';

    /**
     * @param non-empty-string|null $subjectAttribute
     * @param non-empty-string      $nameIdFormat
     * @param non-empty-string|null $emailAttribute
     */
    private function __construct(
        public ?string $subjectAttribute,
        public string $nameIdFormat,
        public ?string $emailAttribute,
        public bool $emailTrusted,
        public ?string $nameAttribute,
        public ?string $givenNameAttribute,
        public ?string $familyNameAttribute,
        public bool $signRequests,
        public bool $requireEncryption,
        public bool $requireGcm,
    ) {
    }

    /** @throws InvalidValue */
    public static function of(
        ?string $subjectAttribute = null,
        ?string $nameIdFormat = null,
        ?string $emailAttribute = null,
        bool $emailTrusted = false,
        ?string $nameAttribute = null,
        ?string $givenNameAttribute = null,
        ?string $familyNameAttribute = null,
        bool $signRequests = true,
        bool $requireEncryption = false,
        bool $requireGcm = false,
    ): self {
        $names = [$subjectAttribute, $emailAttribute, $nameAttribute, $givenNameAttribute, $familyNameAttribute];
        foreach ($names as $name) {
            if ($name !== null && preg_match(self::ATTRIBUTE, $name) !== 1) {
                throw new InvalidValue('A SAML attribute name is 1 to 255 visible characters.');
            }
        }
        if ($subjectAttribute === '' || $emailAttribute === '') {
            throw new InvalidValue('A SAML attribute name is 1 to 255 visible characters.');
        }
        $format = $nameIdFormat ?? self::PERSISTENT;
        $urn = '/^urn:oasis:names:tc:SAML:(1\.1|2\.0):nameid-format:[A-Za-z]+$/D';
        if ($format === '' || preg_match($urn, $format) !== 1) {
            throw new InvalidValue('A NameID format is one of the SAML nameid-format URNs.');
        }

        return new self(
            $subjectAttribute,
            $format,
            $emailAttribute,
            $emailTrusted,
            $nameAttribute,
            $givenNameAttribute,
            $familyNameAttribute,
            $signRequests,
            $requireEncryption,
            $requireGcm,
        );
    }

    /** @return array<string, string|bool|null> As stored, and as the Management API shows it. */
    public function toArray(): array
    {
        return [
            'subject_attribute' => $this->subjectAttribute,
            'name_id_format' => $this->nameIdFormat,
            'email_attribute' => $this->emailAttribute,
            'email_trusted' => $this->emailTrusted,
            'name_attribute' => $this->nameAttribute,
            'given_name_attribute' => $this->givenNameAttribute,
            'family_name_attribute' => $this->familyNameAttribute,
            'sign_requests' => $this->signRequests,
            'require_encryption' => $this->requireEncryption,
            'require_gcm' => $this->requireGcm,
        ];
    }

    /**
     * @param array<array-key, mixed> $stored
     *
     * @throws InvalidValue
     */
    public static function fromArray(array $stored): self
    {
        $string = static function (string $key) use ($stored): ?string {
            /** @var mixed $value */
            $value = $stored[$key] ?? null;

            return is_string($value) ? $value : null;
        };
        $bool = static function (string $key, bool $default) use ($stored): bool {
            /** @var mixed $value */
            $value = $stored[$key] ?? null;

            return is_bool($value) ? $value : $default;
        };

        return self::of(
            $string('subject_attribute'),
            $string('name_id_format'),
            $string('email_attribute'),
            $bool('email_trusted', false),
            $string('name_attribute'),
            $string('given_name_attribute'),
            $string('family_name_attribute'),
            $bool('sign_requests', true),
            $bool('require_encryption', false),
            $bool('require_gcm', false),
        );
    }
}
