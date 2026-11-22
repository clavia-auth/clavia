<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Authentication\Passkey\WebAuthnPurpose;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;
use Exception;
use JsonException;
use ValueError;

/**
 * WebAuthn ceremonies in Redis, as JSON under `webauthn:<digest of the handle>`.
 *
 * The lifetime is set once, when the ceremony opens, and never extended. A challenge is claimed
 * with `GETDEL`: whoever asks first holds it and nobody else can, so it works once, and it is
 * gone whether the response that follows is good or bad. The login state and the second-factor
 * challenge it is bound to are kept as their digests, as the handles themselves are secrets a
 * browser could present.
 */
final readonly class RedisWebAuthnChallengeStore implements WebAuthnChallengeStore
{
    private const string PREFIX = 'webauthn';

    private const string INSTANT = 'Y-m-d\\TH:i:s.uP';

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function open(
        #[\SensitiveParameter] string $handle,
        WebAuthnChallenge $challenge,
        int $lifetimeSeconds,
    ): void {
        $this->redis->client()->set(
            Keys::forSecret(self::PREFIX, $handle),
            json_encode([
                'challenge' => Base64Url::encode($challenge->challenge),
                'purpose' => $challenge->purpose->value,
                'user_id' => $challenge->userId?->value,
                'context' => $challenge->context?->toString(),
                'expires_at' => $challenge->expiresAt->format(self::INSTANT),
            ], JSON_THROW_ON_ERROR),
            ['EX' => $lifetimeSeconds],
        );
    }

    #[\Override]
    public function claim(#[\SensitiveParameter] string $handle): ?WebAuthnChallenge
    {
        if ($handle === '') {
            return null;
        }

        /** @var mixed $raw */
        $raw = $this->redis->client()->getDel(Keys::forSecret(self::PREFIX, $handle));
        if (! is_string($raw)) {
            return null;
        }

        try {
            /** @var mixed $data */
            $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
            if (! is_array($data)) {
                return null;
            }
            /** @var mixed $challenge */
            $challenge = $data['challenge'] ?? null;
            /** @var mixed $purpose */
            $purpose = $data['purpose'] ?? null;
            /** @var mixed $userId */
            $userId = $data['user_id'] ?? null;
            /** @var mixed $context */
            $context = $data['context'] ?? null;
            /** @var mixed $expiresAt */
            $expiresAt = $data['expires_at'] ?? null;
            if (
                ! is_string($challenge) || ! is_string($purpose) || ! is_string($expiresAt)
                || ($userId !== null && ! is_string($userId))
                || ($context !== null && ! is_string($context))
            ) {
                return null;
            }

            return WebAuthnChallenge::reconstitute(
                Base64Url::decode($challenge),
                WebAuthnPurpose::from($purpose),
                $userId === null ? null : UserId::fromString($userId),
                $context === null ? null : Digest::fromHex($context),
                new DateTimeImmutable($expiresAt),
            );
        } catch (JsonException | InvalidValue | ValueError | Exception) {
            // An entry this code cannot read is an entry that is not there.
            return null;
        }
    }
}
