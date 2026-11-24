<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users\Import;

use Clavia\Application\Port\PasswordHasher;
use JsonException;
use stdClass;

/**
 * Reads one line of an import: a JSON object describing one account, held to the Management API's
 * rules for a new user, with a password hash instead of a password.
 *
 * - `email` is required; `email_verified` and `is_active` are booleans; `name`, `given_name`,
 *   `family_name`, `nickname`, `picture` and `locale` are strings;
 * - `password_hash` is one this server can verify (`PBKDF2-HMAC-SHA-256`, at any count from 1,000):
 *   anything else is refused, never stored for a sign-in that could not succeed. A hash at another
 *   count is replaced at the account's first sign-in;
 * - `user_id`, `connection`, `created_at` and `updated_at`, which an export writes, are ignored: the
 *   account gets a new id, the job's pool, and today as its creation;
 * - a plaintext `password`, or any member not listed, refuses the line: an import is as strict as
 *   the API, and a password is never carried in a file.
 *
 * A refusal names the field, never its value.
 */
final readonly class ImportLine
{
    private const array PROFILE = ['name', 'given_name', 'family_name', 'nickname', 'picture', 'locale'];
    private const array KNOWN = ['email', 'email_verified', 'is_active', 'password_hash', ...self::PROFILE];

    /** What an export adds, saying where an account came from: ignored, so an export imports as it is. */
    private const array EXPORTED = ['user_id', 'connection', 'created_at', 'updated_at'];

    public function __construct(private PasswordHasher $hasher)
    {
    }

    public function read(#[\SensitiveParameter] string $line): ImportedAccount|ImportRefusal
    {
        try {
            /** @var mixed $decoded */
            $decoded = json_decode($line, false, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return new ImportRefusal('invalid_json', 'The line is not valid JSON.');
        }
        if (! $decoded instanceof stdClass) {
            return new ImportRefusal('invalid_json', 'The line is not a JSON object.');
        }
        $members = array_diff_key(get_object_vars($decoded), array_flip(self::EXPORTED));
        foreach (array_keys($members) as $name) {
            if (! in_array($name, self::KNOWN, true)) {
                return new ImportRefusal('invalid_field', sprintf("'%s' is not a field an import takes.", $name));
            }
        }

        $email = $members['email'] ?? null;
        if (! is_string($email)) {
            return new ImportRefusal('invalid_field', "'email' is required, a string.");
        }
        foreach (['email_verified', 'is_active'] as $flag) {
            if (array_key_exists($flag, $members) && ! is_bool($members[$flag])) {
                return new ImportRefusal('invalid_field', sprintf("'%s' must be true or false.", $flag));
            }
        }
        $profile = [];
        foreach (self::PROFILE as $field) {
            if (! array_key_exists($field, $members)) {
                continue;
            }
            if (! is_string($members[$field])) {
                return new ImportRefusal('invalid_field', sprintf("'%s' must be a string.", $field));
            }
            $profile[$field] = $members[$field];
        }
        $hash = $members['password_hash'] ?? null;
        if ($hash !== null && (! is_string($hash) || $hash === '' || ! $this->hasher->canVerify($hash))) {
            return new ImportRefusal(
                'unsupported_hash',
                "'password_hash' is not in a format this server verifies: PBKDF2-HMAC-SHA-256 "
                . '($pbkdf2-sha256$i=…$salt$key).',
            );
        }

        return new ImportedAccount(
            $email,
            $hash,
            ($members['email_verified'] ?? false) === true,
            ($members['is_active'] ?? true) === true,
            $profile,
        );
    }
}
