<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Provisioning;

use Clavia\Domain\Identity\Profile;
use Clavia\Domain\Shared\InvalidValue;
use stdClass;

/**
 * A SCIM `User` resource as a directory sends it (RFC 7643 §4.1), read for what this server keeps
 * (docs/design/scim-provisioning.md §2):
 *
 * - `userName` (required, unique per connection, compared ignoring case: §4.1.1), `externalId` (§3),
 *   `active`;
 * - `displayName`, `name.formatted`, `name.givenName`, `name.familyName`, `nickName`, `locale`: the
 *   account's profile;
 * - `emails`: the account's address is the primary one (or the first), or `userName` when it is an
 *   address and no email is given.
 *
 * Attribute names are case-insensitive (§2.1). Everything else is ignored, as directories send fixed
 * sets with their own extensions and fail against a server that refuses them; `password` alone is
 * refused, since a password in a provisioning payload is a password in a directory's logs. Every
 * refusal names the attribute and the rule, never the value.
 */
final readonly class ScimUser
{
    public const string SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';

    private const int MAX_LENGTH = 255;

    /**
     * @param non-empty-string        $userName
     * @param non-empty-string|null   $externalId
     * @param list<non-empty-string>  $emails     The addresses sent, the primary one first.
     */
    private function __construct(
        public string $userName,
        public ?string $externalId,
        public bool $active,
        public ?string $displayName,
        public ?string $formattedName,
        public ?string $givenName,
        public ?string $familyName,
        public ?string $nickName,
        public ?string $locale,
        public array $emails,
    ) {
    }

    /**
     * @throws InvalidValue When a supported attribute has the wrong type or shape, `userName` is
     *                      missing, or a password is sent.
     */
    public static function fromJson(stdClass $resource): self
    {
        $attributes = self::attributes($resource);
        if (($attributes['password'] ?? null) !== null) {
            throw new InvalidValue("'password' is not accepted: an account's password is never provisioned.");
        }
        $userName = self::text($attributes, 'userName');
        if ($userName === null) {
            throw new InvalidValue("'userName' is required.");
        }
        $active = $attributes['active'] ?? true;
        if (! is_bool($active)) {
            throw new InvalidValue("'active' is a boolean.");
        }
        $name = $attributes['name'] ?? null;
        if ($name !== null && ! $name instanceof stdClass) {
            throw new InvalidValue("'name' is an object.");
        }
        $names = $name === null ? [] : self::attributes($name);
        $locale = self::text($attributes, 'locale');
        if ($locale !== null) {
            try {
                Profile::of(locale: $locale);
            } catch (InvalidValue) {
                throw new InvalidValue("'locale' is a language tag, such as en-US.");
            }
        }

        return new self(
            $userName,
            self::text($attributes, 'externalId'),
            $active,
            self::text($attributes, 'displayName'),
            self::text($names, 'formatted', 'name.formatted'),
            self::text($names, 'givenName', 'name.givenName'),
            self::text($names, 'familyName', 'name.familyName'),
            self::text($attributes, 'nickName'),
            $locale,
            self::emails($attributes['emails'] ?? null),
        );
    }

    /**
     * The account's address: the primary email, or `userName` when it is an address and no email is
     * given.
     *
     * @return non-empty-string
     *
     * @throws InvalidValue When there is none.
     */
    public function address(): string
    {
        if ($this->emails !== []) {
            return $this->emails[0];
        }
        if (preg_match('/^[^\s@]+@[^\s@]+$/D', $this->userName) === 1) {
            return $this->userName;
        }

        throw new InvalidValue("'emails' is required when 'userName' is not an email address.");
    }

    /** What the account's profile holds: the display name first, then the formatted name. */
    public function profile(): Profile
    {
        return Profile::of(
            name: $this->displayName ?? $this->formattedName,
            givenName: $this->givenName,
            familyName: $this->familyName,
            nickname: $this->nickName,
            locale: $this->locale,
        );
    }

    /**
     * What names the person to an enterprise connection: the attribute the token says.
     *
     * @return non-empty-string|null
     */
    public function subject(SubjectAttribute $attribute): ?string
    {
        return match ($attribute) {
            SubjectAttribute::ExternalId => $this->externalId,
            SubjectAttribute::UserName => $this->userName,
        };
    }

    /**
     * The members of an object by their name in lower case: SCIM names are case-insensitive. Never
     * read back as a key: the name is the lookup only.
     *
     * @return array<string, mixed>
     */
    private static function attributes(stdClass $object): array
    {
        /** @var array<array-key, mixed> $members */
        $members = get_object_vars($object);
        $names = array_map(static fn (int|string $name): string => strtolower((string) $name), array_keys($members));

        return array_combine($names, array_values($members));
    }

    /**
     * @param array<string, mixed> $attributes
     *
     * @return non-empty-string|null
     */
    private static function text(array $attributes, string $name, ?string $path = null): ?string
    {
        /** @var mixed $value */
        $value = $attributes[strtolower($name)] ?? null;
        if ($value === null) {
            return null;
        }
        if (
            ! is_string($value)
            || ! mb_check_encoding($value, 'UTF-8')
            || mb_strlen($value, 'UTF-8') > self::MAX_LENGTH
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
        ) {
            throw new InvalidValue(sprintf(
                "'%s' is a string of at most %d characters, without control characters.",
                $path ?? $name,
                self::MAX_LENGTH,
            ));
        }

        return $value === '' ? null : $value;
    }

    /**
     * The addresses of `emails`, the primary one first (RFC 7643 §2.4: at most one is primary).
     *
     * @return list<non-empty-string>
     */
    private static function emails(mixed $emails): array
    {
        if ($emails === null) {
            return [];
        }
        if (! is_array($emails) || ! array_is_list($emails)) {
            throw new InvalidValue("'emails' is an array of objects.");
        }
        $primary = [];
        $others = [];
        /** @var mixed $email */
        foreach ($emails as $email) {
            if (! $email instanceof stdClass) {
                throw new InvalidValue("'emails' is an array of objects.");
            }
            $member = self::attributes($email);
            $value = self::text($member, 'value', 'emails.value');
            if ($value === null || preg_match('/^[^\s@]+@[^\s@]+$/D', $value) !== 1) {
                throw new InvalidValue("'emails.value' is an email address.");
            }
            $isPrimary = $member['primary'] ?? false;
            if (! is_bool($isPrimary)) {
                throw new InvalidValue("'emails.primary' is a boolean.");
            }
            if ($isPrimary) {
                $primary[] = $value;
            } else {
                $others[] = $value;
            }
        }
        if (count($primary) > 1) {
            throw new InvalidValue("At most one of 'emails' is primary.");
        }

        return [...$primary, ...$others];
    }
}
